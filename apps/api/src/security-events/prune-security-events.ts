import { pathToFileURL } from "node:url";
import { type AppConfig, loadConfig } from "../config.js";
import { createDatabaseClient } from "../db/client.js";
import { PostgresIdentityStore } from "../db/postgres-identity-store.js";
import { readOptionalPositiveInteger, resolveRetentionCutoff } from "../maintenance/retention.js";
import {
  DefaultSecurityEventService,
  type PruneSecurityEventsInput
} from "./security-event-service.js";

export { resolveRetentionCutoff } from "../maintenance/retention.js";

export type PruneSecurityEventsRuntimeOptions = PruneSecurityEventsInput & {
  now?: Date;
};

export type PruneSecurityEventsCommandResult = {
  retentionDays: number;
  cutoff: string;
  deletedCount: number;
  batches: number;
  complete: boolean;
};

export function resolvePruneOptions(env: NodeJS.ProcessEnv): PruneSecurityEventsInput {
  return {
    batchSize: readOptionalPositiveInteger(env, "SECURITY_EVENT_PRUNE_BATCH_SIZE"),
    maxBatches: readOptionalPositiveInteger(env, "SECURITY_EVENT_PRUNE_MAX_BATCHES")
  };
}

export async function pruneSecurityEvents(
  config: AppConfig,
  options: PruneSecurityEventsRuntimeOptions = {}
): Promise<PruneSecurityEventsCommandResult> {
  const databaseClient = createDatabaseClient(config);

  try {
    const store = new PostgresIdentityStore(databaseClient.db);
    const securityEvents = new DefaultSecurityEventService(store);
    const cutoff = resolveRetentionCutoff(
      options.now ?? new Date(),
      config.SECURITY_EVENT_RETENTION_DAYS
    );
    const result = await securityEvents.pruneBefore(cutoff, {
      batchSize: options.batchSize,
      maxBatches: options.maxBatches
    });

    return {
      retentionDays: config.SECURITY_EVENT_RETENTION_DAYS,
      cutoff: result.cutoff.toISOString(),
      deletedCount: result.deletedCount,
      batches: result.batches,
      complete: result.complete
    };
  } finally {
    await databaseClient.close();
  }
}

async function main(): Promise<void> {
  const result = await pruneSecurityEvents(loadConfig(), resolvePruneOptions(process.env));
  console.log(JSON.stringify(result));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
