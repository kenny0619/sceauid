const dayMs = 24 * 60 * 60 * 1000;

export type BatchPruneOptions = {
  batchSize?: number;
  maxBatches?: number;
};

export type BatchPruneResult = {
  deletedCount: number;
  batches: number;
  complete: boolean;
};

export function readOptionalPositiveInteger(
  env: NodeJS.ProcessEnv,
  name: string
): number | undefined {
  const value = env[name];

  if (value === undefined || value === "") {
    return undefined;
  }

  const parsed = Number(value);

  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error(`${name} must be a positive integer`);
  }

  return parsed;
}

export function resolveRetentionCutoff(now: Date, retentionDays: number): Date {
  return new Date(now.getTime() - retentionDays * dayMs);
}

function normalizePositiveInteger(
  value: number | undefined,
  fallback: number,
  max: number
): number {
  if (value === undefined) {
    return fallback;
  }

  if (!Number.isFinite(value) || value < 1) {
    return fallback;
  }

  return Math.min(Math.floor(value), max);
}

export async function pruneInBatches(
  deleteBatch: (limit: number) => Promise<number>,
  options: BatchPruneOptions = {}
): Promise<BatchPruneResult> {
  const batchSize = normalizePositiveInteger(options.batchSize, 1000, 10_000);
  const maxBatches = normalizePositiveInteger(options.maxBatches, 1000, 10_000);
  let deletedCount = 0;
  let batches = 0;

  while (batches < maxBatches) {
    const deleted = await deleteBatch(batchSize);
    deletedCount += deleted;

    if (deleted === 0 || deleted < batchSize) {
      return {
        deletedCount,
        batches: deleted > 0 ? batches + 1 : batches,
        complete: true
      };
    }

    batches += 1;
  }

  return {
    deletedCount,
    batches,
    complete: false
  };
}
