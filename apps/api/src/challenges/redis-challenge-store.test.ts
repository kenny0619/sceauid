import { describe, expect, it } from "vitest";
import type { ChallengeRecord } from "../domain/storage.js";
import { RedisChallengeStore, type RedisChallengeStoreClient } from "./redis-challenge-store.js";

function createFakeRedisClient() {
  const values = new Map<string, string>();
  const sets: Array<{
    key: string;
    value: string;
    expirationSeconds: number;
  }> = [];

  const client: RedisChallengeStoreClient = {
    async set(key, value, options) {
      values.set(key, value);
      sets.push({
        key,
        value,
        expirationSeconds: options.expiration.value
      });
    },
    async getDel(key) {
      const value = values.get(key) ?? null;
      values.delete(key);
      return value;
    }
  };

  return { client, values, sets };
}

const now = new Date("2026-06-01T12:00:00.000Z");

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

describe("RedisChallengeStore", () => {
  it("stores challenges with a Redis expiry derived from expiresAt", async () => {
    const { client, sets } = createFakeRedisClient();
    const store = new RedisChallengeStore(client, { now: () => now });

    await store.createChallenge(createChallenge());

    expect(sets).toHaveLength(1);
    expect(sets[0]).toMatchObject({
      key: "sceauid:challenge:challenge-id",
      expirationSeconds: 300
    });
    expect(JSON.parse(sets[0]?.value ?? "{}")).toMatchObject({
      id: "challenge-id",
      purpose: "passkey_registration",
      subject: "user-id",
      payload: {
        challenge: "public-challenge",
        userHandle: "user-handle"
      },
      expiresAt: "2026-06-01T12:05:00.000Z"
    });
  });

  it("rejects already-expired challenge creation", async () => {
    const { client } = createFakeRedisClient();
    const store = new RedisChallengeStore(client, { now: () => now });

    await expect(
      store.createChallenge(createChallenge({ expiresAt: new Date("2026-06-01T12:00:00.000Z") }))
    ).rejects.toThrow("Challenge expiry must be in the future");
  });

  it("atomically consumes matching active challenges once", async () => {
    const { client } = createFakeRedisClient();
    const store = new RedisChallengeStore(client, { now: () => now });
    await store.createChallenge(createChallenge());

    await expect(store.consumeChallenge("challenge-id", "passkey_registration")).resolves.toEqual(
      createChallenge()
    );
    await expect(
      store.consumeChallenge("challenge-id", "passkey_registration")
    ).resolves.toBeNull();
  });

  it("rejects mismatched purpose and malformed payload after consume", async () => {
    const { client, values } = createFakeRedisClient();
    const store = new RedisChallengeStore(client, { now: () => now });
    await store.createChallenge(createChallenge());

    await expect(store.consumeChallenge("challenge-id", "passkey_login")).resolves.toBeNull();
    await expect(
      store.consumeChallenge("challenge-id", "passkey_registration")
    ).resolves.toBeNull();

    values.set("sceauid:challenge:malformed", JSON.stringify({ id: "malformed" }));

    await expect(store.consumeChallenge("malformed", "passkey_registration")).resolves.toBeNull();
  });
});
