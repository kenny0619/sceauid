# Stale Identity Maintenance

SceauID stores sessions and recovery requests as durable identity records. Production deployments should prune stale records so expired token hashes and completed recovery handoff state do not accumulate indefinitely.

## Retention Windows

Session and recovery request retention are configured separately:

```txt
SESSION_RECORD_RETENTION_DAYS=90
RECOVERY_REQUEST_RETENTION_DAYS=90
```

Session pruning deletes:

- expired sessions whose `expiresAt` is older than the session retention cutoff
- revoked sessions whose `revokedAt` is older than the session retention cutoff

Recovery request pruning deletes:

- completed requests whose `completedAt` is older than the recovery request retention cutoff
- cancelled, expired, pending, or verified requests whose `expiresAt` is older than the recovery request retention cutoff

Active sessions and unexpired recovery requests are not eligible for pruning.

## Prune Command

Run the prune command from the API package:

```sh
pnpm --filter @sceauid/api identity:prune-stale
```

The command prints a JSON summary:

```json
{
  "sessions": {
    "retentionDays": 90,
    "cutoff": "2026-03-27T12:00:00.000Z",
    "deletedCount": 42,
    "batches": 1,
    "complete": true
  },
  "recoveryRequests": {
    "retentionDays": 90,
    "cutoff": "2026-03-27T12:00:00.000Z",
    "deletedCount": 8,
    "batches": 1,
    "complete": true
  }
}
```

Schedule this command from cron, a platform scheduler, or deployment automation. A daily run is enough for most deployments.

## Batch Controls

Pruning runs in bounded batches.

```txt
STALE_IDENTITY_PRUNE_BATCH_SIZE=1000
STALE_IDENTITY_PRUNE_MAX_BATCHES=1000
```

If a target returns `"complete": false`, the command reached `STALE_IDENTITY_PRUNE_MAX_BATCHES` before all eligible rows were deleted. Run it again or raise the batch count for the next maintenance window.
