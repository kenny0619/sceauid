import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { InMemoryChallengeStore } from "../challenges/in-memory-challenge-store.js";
import { createPostgresStoreTestContext, createTestUser } from "../db/postgres-test-harness.js";
import { DefaultSecurityEventService } from "../security-events/security-event-service.js";
import { DefaultPasskeyLoginStartService } from "./passkey-login-start-service.js";

const context = createPostgresStoreTestContext();
const now = new Date("2026-06-01T12:00:00.000Z");

afterAll(async () => {
  await context.cleanup();
  await context.client.close();
});

beforeEach(async () => {
  await context.cleanup();
});

describe("DefaultPasskeyLoginStartService integration", () => {
  it("generates scoped login options and stores the authentication challenge", async () => {
    const user = await createTestUser(context);
    await context.store.createPasskeyCredential({
      userId: user.id,
      credentialId: "credential-id",
      publicKey: "public-key",
      signCount: 1
    });
    const challengeStore = new InMemoryChallengeStore({ now: () => now });
    const securityEvents = new DefaultSecurityEventService(context.store);
    const service = new DefaultPasskeyLoginStartService(
      context.store,
      challengeStore,
      {
        rpId: "localhost",
        origin: "http://localhost:3000"
      },
      {
        now: () => now,
        createLoginId: () => "login-id",
        securityEvents
      }
    );

    const result = await service.start({ userId: user.id });
    const challenge = await challengeStore.consumeChallenge("login-id", "passkey_login");

    expect(result).toMatchObject({
      loginId: "login-id",
      expiresAt: new Date("2026-06-01T12:05:00.000Z"),
      options: {
        rpId: "localhost",
        timeout: 300_000,
        userVerification: "preferred",
        allowCredentials: [
          {
            id: "credential-id",
            type: "public-key"
          }
        ]
      }
    });
    expect(result.options.challenge).toEqual(expect.any(String));
    expect(challenge).toEqual({
      id: "login-id",
      purpose: "passkey_login",
      subject: user.id,
      payload: {
        challenge: result.options.challenge,
        rpId: "localhost",
        origin: "http://localhost:3000",
        userId: user.id
      },
      expiresAt: new Date("2026-06-01T12:05:00.000Z")
    });
    await expect(
      context.store.listSecurityEventsForUser({ userId: user.id, limit: 10 })
    ).resolves.toMatchObject({
      events: [
        {
          userId: user.id,
          eventType: "login_started",
          outcome: "pending",
          metadata: {
            loginId: "login-id",
            mode: "scoped",
            allowedCredentials: 1
          }
        }
      ]
    });
  });

  it("generates discoverable login options without credential allow-listing", async () => {
    const challengeStore = new InMemoryChallengeStore({ now: () => now });
    const service = new DefaultPasskeyLoginStartService(context.store, challengeStore, {
      rpId: "localhost",
      origin: "http://localhost:3000"
    });

    const result = await service.start();
    const challenge = await challengeStore.consumeChallenge(result.loginId, "passkey_login");

    expect(result.options.allowCredentials).toBeUndefined();
    expect(challenge).toMatchObject({
      id: result.loginId,
      purpose: "passkey_login",
      subject: "discoverable",
      payload: {
        challenge: result.options.challenge,
        rpId: "localhost",
        origin: "http://localhost:3000",
        userId: null
      }
    });
  });
});
