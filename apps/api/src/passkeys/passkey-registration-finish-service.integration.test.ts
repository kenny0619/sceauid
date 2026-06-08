import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { InMemoryChallengeStore } from "../challenges/in-memory-challenge-store.js";
import { createPostgresStoreTestContext, createTestUser } from "../db/postgres-test-harness.js";
import { DefaultSecurityEventService } from "../security-events/security-event-service.js";
import { DefaultSessionService } from "../sessions/session-service.js";
import type { SessionToken } from "../sessions/session-token.js";
import { DefaultPasskeyRegistrationFinishService } from "./passkey-registration-finish-service.js";
import type { VerifyRegistrationResponse } from "./passkey-registration-finish-service.js";

const context = createPostgresStoreTestContext();
const now = new Date("2026-06-01T12:00:00.000Z");

afterAll(async () => {
  await context.cleanup();
  await context.client.close();
});

beforeEach(async () => {
  await context.cleanup();
});

const verifyRegistration: VerifyRegistrationResponse = async () => ({
  verified: true,
  registrationInfo: {
    fmt: "none",
    aaguid: "00000000-0000-0000-0000-000000000000",
    credential: {
      id: "credential-id",
      publicKey: new Uint8Array([1, 2, 3]),
      counter: 7
    },
    credentialType: "public-key",
    attestationObject: new Uint8Array([4, 5, 6]),
    userVerified: true,
    credentialDeviceType: "multiDevice",
    credentialBackedUp: true,
    origin: "http://localhost:3000",
    rpID: "localhost"
  }
});

describe("DefaultPasskeyRegistrationFinishService integration", () => {
  it("consumes the stored ceremony and persists the verified credential", async () => {
    const user = await createTestUser(context);
    const challengeStore = new InMemoryChallengeStore({ now: () => now });
    await challengeStore.createChallenge({
      id: "registration-id",
      purpose: "passkey_registration",
      subject: user.id,
      payload: {
        challenge: "public-challenge",
        userHandle: "dXNlci1pZA",
        rpId: "localhost",
        origin: "http://localhost:3000"
      },
      expiresAt: new Date("2026-06-01T12:05:00.000Z")
    });
    const securityEvents = new DefaultSecurityEventService(context.store);
    const service = new DefaultPasskeyRegistrationFinishService(
      context.store,
      challengeStore,
      {
        rpId: "localhost",
        origin: "http://localhost:3000"
      },
      { verifyRegistration, securityEvents }
    );

    const result = await service.finish({
      registrationId: "registration-id",
      credential: {
        id: "credential-id",
        rawId: "credential-id",
        response: {
          clientDataJSON: "client-data",
          attestationObject: "attestation-object"
        },
        clientExtensionResults: {},
        type: "public-key"
      },
      deviceName: "MacBook"
    });

    await expect(context.store.findPasskeyByCredentialId("credential-id")).resolves.toMatchObject({
      id: result.credential.id,
      userId: user.id,
      credentialId: "credential-id",
      publicKey: "AQID",
      signCount: 7,
      deviceName: "MacBook",
      revokedAt: null
    });
    await expect(
      challengeStore.consumeChallenge("registration-id", "passkey_registration")
    ).resolves.toBeNull();
    await expect(
      context.store.listSecurityEventsForUser({ userId: user.id, limit: 10 })
    ).resolves.toMatchObject({
      events: [
        {
          userId: user.id,
          eventType: "passkey_registered",
          outcome: "success",
          metadata: {
            credentialId: "credential-id",
            deviceName: "MacBook",
            registrationContext: {
              flow: "standard"
            },
            registrationId: "registration-id"
          }
        }
      ]
    });
  });

  it("revokes recovery sessions after recovery passkey registration succeeds", async () => {
    const user = await createTestUser(context);
    const challengeStore = new InMemoryChallengeStore({ now: () => now });
    const sessionService = new DefaultSessionService(context.store, {
      generateToken: () => "recovery-session-token" as SessionToken,
      now: () => now
    });
    const recoverySession = await sessionService.create({
      userId: user.id,
      deviceLabel: "Recovery session",
      ttlSeconds: 300
    });
    await challengeStore.createChallenge({
      id: "registration-id",
      purpose: "passkey_registration",
      subject: user.id,
      payload: {
        challenge: "public-challenge",
        userHandle: "dXNlci1pZA",
        rpId: "localhost",
        origin: "http://localhost:3000",
        registrationContext: {
          flow: "recovery",
          recoverySessionId: recoverySession.session.id
        }
      },
      expiresAt: new Date("2026-06-01T12:05:00.000Z")
    });
    const securityEvents = new DefaultSecurityEventService(context.store);
    const service = new DefaultPasskeyRegistrationFinishService(
      context.store,
      challengeStore,
      {
        rpId: "localhost",
        origin: "http://localhost:3000"
      },
      { verifyRegistration, securityEvents, sessionService }
    );

    await service.finish({
      registrationId: "registration-id",
      credential: {
        id: "credential-id",
        rawId: "credential-id",
        response: {
          clientDataJSON: "client-data",
          attestationObject: "attestation-object"
        },
        clientExtensionResults: {},
        type: "public-key"
      },
      deviceName: "iPhone"
    });

    const sessions = await context.store.listSessionsForUser(user.id);
    expect(sessions.find((session) => session.id === recoverySession.session.id)).toMatchObject({
      revokedAt: now
    });
    const events = await context.store.listSecurityEventsForUser({ userId: user.id, limit: 10 });
    expect(events.events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          userId: user.id,
          sessionId: recoverySession.session.id,
          eventType: "session_revoked",
          outcome: "success",
          metadata: expect.objectContaining({
            reason: "recovery_passkey_registered",
            registrationId: "registration-id",
            registrationContext: {
              flow: "recovery",
              recoverySessionId: recoverySession.session.id
            }
          })
        }),
        expect.objectContaining({
          userId: user.id,
          eventType: "passkey_registered",
          outcome: "success",
          metadata: expect.objectContaining({
            recoverySessionFinalized: true,
            registrationContext: {
              flow: "recovery",
              recoverySessionId: recoverySession.session.id
            },
            registrationId: "registration-id"
          })
        })
      ])
    );
  });
});
