import { createClient } from "redis";
import type { RateLimitResult, RiskStore } from "../domain/storage.js";

export type RedisRiskStoreClient = {
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<unknown>;
  ttl(key: string): Promise<number>;
};

export type RedisRiskStoreOptions = {
  keyPrefix?: string;
  now?: () => Date;
};

const defaultKeyPrefix = "sceauid:risk:";

function resolveResetAt(now: Date, ttlSeconds: number, windowSeconds: number): Date {
  const effectiveTtlSeconds = ttlSeconds > 0 ? ttlSeconds : windowSeconds;

  return new Date(now.getTime() + effectiveTtlSeconds * 1000);
}

export class RedisRiskStore implements RiskStore {
  private readonly keyPrefix: string;
  private readonly now: () => Date;

  constructor(
    private readonly client: RedisRiskStoreClient,
    options: RedisRiskStoreOptions = {}
  ) {
    this.keyPrefix = options.keyPrefix ?? defaultKeyPrefix;
    this.now = options.now ?? (() => new Date());
  }

  async checkRateLimit(
    key: string,
    limit: number,
    windowSeconds: number
  ): Promise<RateLimitResult> {
    const redisKey = this.keyFor(key);
    const count = await this.client.incr(redisKey);

    if (count === 1) {
      await this.client.expire(redisKey, windowSeconds);
    }

    const ttlSeconds = await this.client.ttl(redisKey);
    const remaining = Math.max(limit - count, 0);

    return {
      allowed: count <= limit,
      limit,
      remaining,
      resetAt: resolveResetAt(this.now(), ttlSeconds, windowSeconds)
    };
  }

  private keyFor(key: string): string {
    return `${this.keyPrefix}${key}`;
  }
}

export async function createRedisRiskStore(
  url: string,
  options: RedisRiskStoreOptions = {}
): Promise<{
  store: RedisRiskStore;
  close(): Promise<void>;
}> {
  const client = createClient({ url });
  await client.connect();

  return {
    store: new RedisRiskStore(client, options),
    async close() {
      await client.close();
    }
  };
}
