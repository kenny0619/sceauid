# Security Event Retention

SceauID stores security events as product data for account timelines, recovery review, and incident investigation. Production deployments should prune old events on a schedule that matches their privacy, compliance, and support requirements.

## Retention Window

`SECURITY_EVENT_RETENTION_DAYS` controls the retention window. The default is `365`.

```txt
SECURITY_EVENT_RETENTION_DAYS=365
```

Events older than the calculated cutoff are eligible for deletion. Newer events remain available through `GET /v1/security-events` and `GET /v1/recovery/events`.

## Prune Command

Run the prune command from the API package:

```sh
pnpm --filter @sceauid/api security-events:prune
```

The command prints a JSON summary:

```json
{
  "retentionDays": 365,
  "cutoff": "2025-06-25T12:00:00.000Z",
  "deletedCount": 2400,
  "batches": 3,
  "complete": true
}
```

Schedule this command from your platform scheduler, cron, or deployment automation. A daily run is usually enough for most deployments.

## Batch Controls

Pruning runs in bounded batches to avoid large table locks.

```txt
SECURITY_EVENT_PRUNE_BATCH_SIZE=1000
SECURITY_EVENT_PRUNE_MAX_BATCHES=1000
```

If `complete` is `false`, the command reached `SECURITY_EVENT_PRUNE_MAX_BATCHES` before all eligible rows were deleted. Run it again or increase the batch count for the next maintenance window.
