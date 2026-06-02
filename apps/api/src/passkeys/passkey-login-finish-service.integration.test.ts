import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { InMemoryChallengeStore } from "../challenges/in-memory-challenge-store.js";
import { createPostgresStoreTestContext, createTestUser } from "../db/postgres-test-harness.js";
import { DefaultSessionService } from "../sessions/session-service.js";
import type { SessionToken } from "../sessions/session-token.js";
import {
  DefaultPasskeyLoginFinishService,
  type VerifyAuthenticationResponse
} from "./passkey-login-finish-service.js";

const context = createPostgresStoreTestContext();
const now = new Date("2026-06-01T12:00:00.000Z");

afterAll(async () => {
  await context.cleanup();
  await context.client.close();
});

beforeEach(async () => {
  await context.cleanup();
});

const verifyAuthentication: VerifyAuthenticationResponse = async () => ({
  verified: true,
  authenticationInfo: {
    credentialID: "credential-id",
    newCounter: 8,
    userVerified: true,
    credentialDeviceType: "multiDevice",
    credentialBackedUp: true,
    origin: "http://localhost:3000",
    rpID: "localhost"
  }
});

describe("DefaultPasskeyLoginFinishService integration", () => {
  it("consumes the login challenge, updates passkey usage, and creates a session", async () => {
    const user = await createTestUser(context);
    await context.store.createPasskeyCredential({
      userId: user.id,
      credentialId: "credential-id",
      publicKey: "AQID",
      signCount: 7,
      deviceName: "MacBook"
    });
    const challengeStore = new InMemoryChallengeStore({ now: () => now });
    await challengeStore.createChallenge({
      id: "login-id",
      purpose: "passkey_login",
      subject: user.id,
      payload: {
        challenge: "public-challenge",
        rpId: "localhost",
        origin: "http://localhost:3000",
        userId: user.id
      },
      expiresAt: new Date("2026-06-01T12:05:00.000Z")
    });
    const sessionService = new DefaultSessionService(context.store, {
      now: () => now,
      generateToken: () => "session-token" as SessionToken
    });
    const service = new DefaultPasskeyLoginFinishService(
      context.store,
      challengeStore,
      sessionService,
      {
        rpId: "localhost",
        origin: "http://localhost:3000"
      },
      {
        now: () => now,
        verifyAuthentication
      }
    );

    const result = await service.finish({
      loginId: "login-id",
      credential: {
        id: "credential-id",
        rawId: "credential-id",
        response: {
          clientDataJSON: "client-data",
          authenticatorData: "authenticator-data",
          signature: "signature"
        },
        clientExtensionResults: {},
        type: "public-key"
      },
      deviceLabel: "Safari on macOS",
      context: {
        ipHash: "ip-hash",
        userAgent: "test-agent"
      }
    });

    await expect(context.store.findPasskeyByCredentialId("credential-id")).resolves.toMatchObject({
      signCount: 8,
      lastUsedAt: now
    });
    await expect(
      context.store.findSessionByTokenHash(result.session.session.tokenHash)
    ).resolves.toMatchObject({
      userId: user.id,
      deviceLabel: "Safari on macOS",
      ipHash: "ip-hash",
      userAgent: "test-agent",
      revokedAt: null
    });
    await expect(challengeStore.consumeChallenge("login-id", "passkey_login")).resolves.toBeNull();
    expect(result).toMatchObject({
      userId: user.id,
      credential: {
        credentialId: "credential-id",
        signCount: 8
      },
      session: {
        token: "session-token"
      }
    });
  });
});
