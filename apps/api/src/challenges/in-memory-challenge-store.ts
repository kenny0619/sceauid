import type { ChallengePurpose, ChallengeRecord, ChallengeStore } from "../domain/storage.js";

export type InMemoryChallengeStoreOptions = {
  now?: () => Date;
};

function cloneRecord(record: ChallengeRecord): ChallengeRecord {
  return {
    ...record,
    payload: { ...record.payload },
    expiresAt: new Date(record.expiresAt)
  };
}

export class InMemoryChallengeStore implements ChallengeStore {
  private readonly records = new Map<string, ChallengeRecord>();
  private readonly now: () => Date;

  constructor(options: InMemoryChallengeStoreOptions = {}) {
    this.now = options.now ?? (() => new Date());
  }

  async createChallenge(record: ChallengeRecord): Promise<void> {
    this.records.set(record.id, cloneRecord(record));
  }

  async consumeChallenge(id: string, purpose: ChallengePurpose): Promise<ChallengeRecord | null> {
    const record = this.records.get(id);

    if (!record) {
      return null;
    }

    this.records.delete(id);

    if (record.purpose !== purpose || record.expiresAt <= this.now()) {
      return null;
    }

    return cloneRecord(record);
  }
}
