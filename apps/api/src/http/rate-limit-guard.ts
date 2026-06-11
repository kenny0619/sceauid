import { createHash } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";
import type { RiskStore } from "../domain/storage.js";

export type RateLimitPolicy = {
  keyPrefix: string;
  limit: number;
  windowSeconds: number;
};

export type RateLimitGuardOptions = {
  riskStore: RiskStore;
  policy: RateLimitPolicy;
  resolveSubject?: (request: FastifyRequest) => string;
};

const retryAfterMinimumSeconds = 1;

function hashSubject(subject: string): string {
  return createHash("sha256").update(subject).digest("base64url");
}

function secondsUntil(resetAt: Date, now = new Date()): number {
  const seconds = Math.ceil((resetAt.getTime() - now.getTime()) / 1000);

  return Math.max(seconds, retryAfterMinimumSeconds);
}

function setRateLimitHeaders(
  reply: FastifyReply,
  result: {
    limit: number;
    remaining: number;
    resetAt: Date;
  }
): void {
  reply.header("ratelimit-limit", result.limit.toString());
  reply.header("ratelimit-remaining", result.remaining.toString());
  reply.header("ratelimit-reset", Math.ceil(result.resetAt.getTime() / 1000).toString());
}

export function createRateLimitGuard(options: RateLimitGuardOptions) {
  return async function rateLimitGuard(request: FastifyRequest, reply: FastifyReply) {
    const subject = options.resolveSubject?.(request) ?? request.ip;
    const key = `${options.policy.keyPrefix}:${hashSubject(subject)}`;
    const result = await options.riskStore.checkRateLimit(
      key,
      options.policy.limit,
      options.policy.windowSeconds
    );

    setRateLimitHeaders(reply, result);

    if (result.allowed) {
      return;
    }

    return reply.status(429).header("retry-after", secondsUntil(result.resetAt).toString()).send({
      error: "rate_limited",
      message: "Too many requests. Try again after the rate limit resets.",
      resetAt: result.resetAt.toISOString()
    });
  };
}
