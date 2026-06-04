import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { InMemoryChallengeStore } from "../challenges/in-memory-challenge-store.js";
import { createPostgresStoreTestContext, createTestUser } from "../db/postgres-test-harness.js";
import { DefaultSecurityEventService } from "../security-events/security-event-service.js";
import { DefaultPasskeyRegistrationStartService } from "./passkey-registration-start-service.js";

const context = createPostgresStoreTestContext();
const now = new Date("2026-06-01T12:00:00.000Z");

afterAll(async () => {
  await context.cleanup();
  await context.client.close();
});

beforeEach(async () => {
  await context.cleanup();
});

describe("DefaultPasskeyRegistrationStartService integration", () => {
  it("generates browser registration options and persists the ceremony challenge", async () => {
    const user = await createTestUser(context);
    await context.store.createPasskeyCredential({
      userId: user.id,
      credentialId: "existing-credential",
      publicKey: "public-key",
      signCount: 1
    });
    const challengeStore = new InMemoryChallengeStore({ now: () => now });
    const securityEvents = new DefaultSecurityEventService(context.store);
    const service = new DefaultPasskeyRegistrationStartService(
      context.store,
      challengeStore,
      {
        rpName: "SceauID",
        rpId: "localhost",
        origin: "http://localhost:3000"
      },
      {
        now: () => now,
        createRegistrationId: () => "registration-id",
        securityEvents
      }
    );

    const result = await service.start({
      userId: user.id,
      userName: "test@example.com"
    });
    const challenge = await challengeStore.consumeChallenge(
      "registration-id",
      "passkey_registration"
    );

    expect(result).toMatchObject({
      registrationId: "registration-id",
      expiresAt: new Date("2026-06-01T12:05:00.000Z"),
      options: {
        rp: {
          name: "SceauID",
          id: "localhost"
        },
        user: {
          name: "test@example.com",
          displayName: "Test User"
        },
        timeout: 300_000,
        attestation: "none",
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "preferred"
        }
      }
    });
    expect(result.options.challenge).toEqual(expect.any(String));
    expect(result.options.user.id).toEqual(expect.any(String));
    expect(result.options.excludeCredentials).toEqual([
      {
        id: "existing-credential",
        type: "public-key"
      }
    ]);
    expect(challenge).toEqual({
      id: "registration-id",
      purpose: "passkey_registration",
      subject: user.id,
      payload: {
        challenge: result.options.challenge,
        userHandle: result.options.user.id,
        rpId: "localhost",
        origin: "http://localhost:3000"
      },
      expiresAt: new Date("2026-06-01T12:05:00.000Z")
    });
    await expect(context.store.listSecurityEventsForUser(user.id, 10)).resolves.toMatchObject([
      {
        userId: user.id,
        eventType: "passkey_registration_started",
        outcome: "pending",
        metadata: {
          registrationId: "registration-id",
          existingActivePasskeys: 1
        }
      }
    ]);
  });
});
