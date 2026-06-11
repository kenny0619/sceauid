import { createClient } from "redis";
import type { ChallengePurpose, ChallengeRecord, ChallengeStore } from "../domain/storage.js";

export type RedisChallengeStoreClient = {
  set(
    key: string,
    value: string,
    options: { expiration: { type: "EX"; value: number } }
  ): Promise<unknown>;
  getDel(key: string): Promise<string | null>;
  ping?(): Promise<string>;
};

export type RedisChallengeStoreOptions = {
  keyPrefix?: string;
  now?: () => Date;
};

type SerializedChallengeRecord = Omit<ChallengeRecord, "expiresAt"> & {
  expiresAt: string;
};

const defaultKeyPrefix = "sceauid:challenge:";

function resolveTtlSeconds(record: ChallengeRecord, now: Date): number {
  const ttlMilliseconds = record.expiresAt.getTime() - now.getTime();

  if (ttlMilliseconds <= 0) {
    throw new Error("Challenge expiry must be in the future");
  }

  return Math.ceil(ttlMilliseconds / 1000);
}

function serializeRecord(record: ChallengeRecord): string {
  return JSON.stringify({
    ...record,
    expiresAt: record.expiresAt.toISOString()
  } satisfies SerializedChallengeRecord);
}

function deserializeRecord(value: string): ChallengeRecord | null {
  const parsed = JSON.parse(value) as Partial<SerializedChallengeRecord>;

  if (
    typeof parsed.id !== "string" ||
    typeof parsed.purpose !== "string" ||
    typeof parsed.subject !== "string" ||
    typeof parsed.expiresAt !== "string" ||
    parsed.payload === null ||
    typeof parsed.payload !== "object" ||
    Array.isArray(parsed.payload)
  ) {
    return null;
  }

  return {
    id: parsed.id,
    purpose: parsed.purpose as ChallengePurpose,
    subject: parsed.subject,
    payload: parsed.payload,
    expiresAt: new Date(parsed.expiresAt)
  };
}

export class RedisChallengeStore implements ChallengeStore {
  private readonly keyPrefix: string;
  private readonly now: () => Date;

  constructor(
    private readonly client: RedisChallengeStoreClient,
    options: RedisChallengeStoreOptions = {}
  ) {
    this.keyPrefix = options.keyPrefix ?? defaultKeyPrefix;
    this.now = options.now ?? (() => new Date());
  }

  async createChallenge(record: ChallengeRecord): Promise<void> {
    await this.client.set(this.keyFor(record.id), serializeRecord(record), {
      expiration: {
        type: "EX",
        value: resolveTtlSeconds(record, this.now())
      }
    });
  }

  async consumeChallenge(id: string, purpose: ChallengePurpose): Promise<ChallengeRecord | null> {
    const value = await this.client.getDel(this.keyFor(id));

    if (!value) {
      return null;
    }

    const record = deserializeRecord(value);

    if (!record || record.purpose !== purpose || record.expiresAt <= this.now()) {
      return null;
    }

    return record;
  }

  private keyFor(id: string): string {
    return `${this.keyPrefix}${id}`;
  }
}

export async function createRedisChallengeStore(
  url: string,
  options: RedisChallengeStoreOptions = {}
): Promise<{
  store: RedisChallengeStore;
  check(): Promise<void>;
  close(): Promise<void>;
}> {
  const client = createClient({ url });
  await client.connect();

  return {
    store: new RedisChallengeStore(client, options),
    async check() {
      await client.ping();
    },
    async close() {
      await client.close();
    }
  };
}
