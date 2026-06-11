# Health And Readiness

SceauID exposes separate liveness and readiness endpoints for production deployments.

## Liveness

```txt
GET /health
```

Use `/health` as a lightweight liveness probe. It confirms that the API process is running and able to answer HTTP requests. It does not check downstream dependencies.

Example response:

```json
{
  "status": "ok",
  "service": "sceauid-api"
}
```

## Readiness

```txt
GET /ready
```

Use `/ready` as a readiness probe before sending traffic to the API. It checks the runtime dependencies that SceauID needs to serve authentication traffic:

- PostgreSQL
- Redis challenge store
- Redis risk store

When every dependency is reachable, the endpoint returns `200`:

```json
{
  "status": "ready",
  "service": "sceauid-api",
  "checks": [
    {
      "name": "postgres",
      "status": "up",
      "durationMs": 4
    },
    {
      "name": "redis:challenges",
      "status": "up",
      "durationMs": 2
    },
    {
      "name": "redis:risk",
      "status": "up",
      "durationMs": 2
    }
  ]
}
```

When any dependency fails, the endpoint returns `503`:

```json
{
  "status": "not_ready",
  "service": "sceauid-api",
  "checks": [
    {
      "name": "postgres",
      "status": "up",
      "durationMs": 4
    },
    {
      "name": "redis:risk",
      "status": "down",
      "durationMs": 1
    }
  ]
}
```

The response intentionally does not expose raw dependency errors. Detailed failure information should stay in server logs and observability tooling.
