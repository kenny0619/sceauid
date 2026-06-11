import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import type { RiskStore } from "../domain/storage.js";
import { createRateLimitGuard } from "./rate-limit-guard.js";

function createRiskStore(allowed: boolean, resetAt = new Date("2026-06-01T12:01:00.000Z")) {
  const calls: Array<{ key: string; limit: number; windowSeconds: number }> = [];
  const riskStore: RiskStore = {
    async checkRateLimit(key, limit, windowSeconds) {
      calls.push({ key, limit, windowSeconds });

      return {
        allowed,
        limit,
        remaining: allowed ? limit - 1 : 0,
        resetAt
      };
    }
  };

  return { calls, riskStore };
}

describe("rate limit guard", () => {
  it("allows requests within the configured limit", async () => {
    const { calls, riskStore } = createRiskStore(true);
    const app = Fastify();
    app.post(
      "/limited",
      {
        preHandler: createRateLimitGuard({
          policy: {
            keyPrefix: "test",
            limit: 2,
            windowSeconds: 60
          },
          resolveSubject: () => "subject",
          riskStore
        })
      },
      async () => ({ ok: true })
    );

    const response = await app.inject({
      method: "POST",
      url: "/limited"
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers["ratelimit-limit"]).toBe("2");
    expect(response.headers["ratelimit-remaining"]).toBe("1");
    expect(response.headers["ratelimit-reset"]).toBe("1780315260");
    expect(calls).toEqual([
      {
        key: expect.stringMatching(/^test:[A-Za-z0-9_-]+$/),
        limit: 2,
        windowSeconds: 60
      }
    ]);

    await app.close();
  });

  it("returns rate limited responses when the configured limit is exceeded", async () => {
    const { riskStore } = createRiskStore(false, new Date(Date.now() + 60_000));
    const app = Fastify();
    app.post(
      "/limited",
      {
        preHandler: createRateLimitGuard({
          policy: {
            keyPrefix: "test",
            limit: 1,
            windowSeconds: 30
          },
          resolveSubject: () => "subject",
          riskStore
        })
      },
      async () => {
        throw new Error("Handler should not be called");
      }
    );

    const response = await app.inject({
      method: "POST",
      url: "/limited"
    });

    expect(response.statusCode).toBe(429);
    expect(response.headers["retry-after"]).toBe("60");
    expect(response.headers["ratelimit-limit"]).toBe("1");
    expect(response.headers["ratelimit-remaining"]).toBe("0");
    expect(response.json()).toMatchObject({
      error: "rate_limited",
      message: "Too many requests. Try again after the rate limit resets."
    });

    await app.close();
  });
});
