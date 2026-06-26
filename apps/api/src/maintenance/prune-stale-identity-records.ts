import { pathToFileURL } from "node:url";
import { type AppConfig, loadConfig } from "../config.js";
import { createDatabaseClient } from "../db/client.js";
import { PostgresIdentityStore } from "../db/postgres-identity-store.js";
import {
  type BatchPruneOptions,
  type BatchPruneResult,
  pruneInBatches,
  readOptionalPositiveInteger,
  resolveRetentionCutoff
} from "./retention.js";

export type PruneStaleIdentityRuntimeOptions = BatchPruneOptions & {
  now?: Date;
};

export type PruneStaleIdentityTargetResult = BatchPruneResult & {
  retentionDays: number;
  cutoff: string;
};

export type PruneStaleIdentityCommandResult = {
  sessions: PruneStaleIdentityTargetResult;
  recoveryRequests: PruneStaleIdentityTargetResult;
};

export function resolveStaleIdentityPruneOptions(env: NodeJS.ProcessEnv): BatchPruneOptions {
  return {
    batchSize: readOptionalPositiveInteger(env, "STALE_IDENTITY_PRUNE_BATCH_SIZE"),
    maxBatches: readOptionalPositiveInteger(env, "STALE_IDENTITY_PRUNE_MAX_BATCHES")
  };
}

async function pruneTarget(
  retentionDays: number,
  now: Date,
  options: BatchPruneOptions,
  deleteBefore: (cutoff: Date, limit: number) => Promise<number>
): Promise<PruneStaleIdentityTargetResult> {
  const cutoff = resolveRetentionCutoff(now, retentionDays);
  const result = await pruneInBatches((limit) => deleteBefore(cutoff, limit), options);

  return {
    retentionDays,
    cutoff: cutoff.toISOString(),
    ...result
  };
}

export async function pruneStaleIdentityRecords(
  config: AppConfig,
  options: PruneStaleIdentityRuntimeOptions = {}
): Promise<PruneStaleIdentityCommandResult> {
  const databaseClient = createDatabaseClient(config);

  try {
    const store = new PostgresIdentityStore(databaseClient.db);
    const now = options.now ?? new Date();
    const pruneOptions = {
      batchSize: options.batchSize,
      maxBatches: options.maxBatches
    };
    const sessions = await pruneTarget(
      config.SESSION_RECORD_RETENTION_DAYS,
      now,
      pruneOptions,
      (cutoff, limit) => store.deleteStaleSessions(cutoff, limit)
    );
    const recoveryRequests = await pruneTarget(
      config.RECOVERY_REQUEST_RETENTION_DAYS,
      now,
      pruneOptions,
      (cutoff, limit) => store.deleteStaleRecoveryRequests(cutoff, limit)
    );

    return {
      sessions,
      recoveryRequests
    };
  } finally {
    await databaseClient.close();
  }
}

async function main(): Promise<void> {
  const result = await pruneStaleIdentityRecords(
    loadConfig(),
    resolveStaleIdentityPruneOptions(process.env)
  );
  console.log(JSON.stringify(result));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
