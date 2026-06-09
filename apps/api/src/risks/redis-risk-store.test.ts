import { describe, expect, it } from "vitest";
import { RedisRiskStore, type RedisRiskStoreClient } from "./redis-risk-store.js";

function createFakeRedisClient() {
  const counts = new Map<string, number>();
  const expiries = new Map<string, number>();

  const client: RedisRiskStoreClient = {
    async expire(key, seconds) {
      expiries.set(key, seconds);
    },
    async incr(key) {
      const count = (counts.get(key) ?? 0) + 1;
      counts.set(key, count);

      return count;
    },
    async ttl(key) {
      return expiries.get(key) ?? -1;
    }
  };

  return { client, counts, expiries };
}

const now = new Date("2026-06-01T12:00:00.000Z");

describe("RedisRiskStore", () => {
  it("allows requests within a fixed window and reports remaining attempts", async () => {
    const { client, expiries } = createFakeRedisClient();
    const store = new RedisRiskStore(client, { now: () => now });

    await expect(store.checkRateLimit("recovery:user-id", 2, 60)).resolves.toEqual({
      allowed: true,
      limit: 2,
      remaining: 1,
      resetAt: new Date("2026-06-01T12:01:00.000Z")
    });
    await expect(store.checkRateLimit("recovery:user-id", 2, 60)).resolves.toMatchObject({
      allowed: true,
      remaining: 0
    });

    expect(expiries).toEqual(new Map([["sceauid:risk:recovery:user-id", 60]]));
  });

  it("rejects requests over the limit until the window resets", async () => {
    const { client } = createFakeRedisClient();
    const store = new RedisRiskStore(client, { now: () => now });

    await store.checkRateLimit("recovery:user-id", 1, 60);

    await expect(store.checkRateLimit("recovery:user-id", 1, 60)).resolves.toEqual({
      allowed: false,
      limit: 1,
      remaining: 0,
      resetAt: new Date("2026-06-01T12:01:00.000Z")
    });
  });
});
