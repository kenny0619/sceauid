import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ChallengeRecord } from "../domain/storage.js";
import { type RedisChallengeStore, createRedisChallengeStore } from "./redis-challenge-store.js";

const redisUrl = process.env.REDIS_URL ?? "redis://localhost:6379";
const now = new Date("2026-06-01T12:00:00.000Z");

let store: RedisChallengeStore;
let close: () => Promise<void>;

beforeAll(async () => {
  const context = await createRedisChallengeStore(redisUrl, {
    keyPrefix: `sceauid:test:${Date.now()}:`,
    now: () => now
  });

  store = context.store;
  close = context.close;
});

afterAll(async () => {
  await close();
});

function createChallenge(overrides: Partial<ChallengeRecord> = {}): ChallengeRecord {
  return {
    id: "challenge-id",
    purpose: "passkey_registration",
    subject: "user-id",
    payload: {
      challenge: "public-challenge",
      userHandle: "user-handle"
    },
    expiresAt: new Date("2026-06-01T12:05:00.000Z"),
    ...overrides
  };
}

describe("RedisChallengeStore integration", () => {
  it("stores and atomically consumes challenges in Redis", async () => {
    await store.createChallenge(createChallenge());

    await expect(store.consumeChallenge("challenge-id", "passkey_registration")).resolves.toEqual(
      createChallenge()
    );
    await expect(
      store.consumeChallenge("challenge-id", "passkey_registration")
    ).resolves.toBeNull();
  });
});
