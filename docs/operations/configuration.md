# Configuration

SceauID uses environment variables for runtime configuration.

Development and test runs include safe local defaults so the project can start quickly with Docker Compose. Production runs are stricter: critical identity and dependency settings must be explicitly configured.

## Required In Production

When `NODE_ENV=production`, these values must be set:

- `DATABASE_URL`
- `REDIS_URL`
- `APP_ORIGIN`
- `WEBAUTHN_RP_ID`

Production also enforces:

- `APP_ORIGIN` must use `https`.
- `WEBAUTHN_RP_ID` must not be `localhost`.

The API fails fast during startup if production configuration is missing or unsafe.

## Variables

```txt
NODE_ENV=production
PORT=4000
DATABASE_URL=postgres://sceauid:secret@db.internal:5432/sceauid
REDIS_URL=redis://redis.internal:6379
SESSION_COOKIE_NAME=sceauid_session
APP_ORIGIN=https://app.example.com
TRUST_PROXY=false
SECURITY_EVENT_RETENTION_DAYS=365
WEBAUTHN_RP_NAME=SceauID
WEBAUTHN_RP_ID=app.example.com
```

`SESSION_COOKIE_NAME`, `SECURITY_EVENT_RETENTION_DAYS`, and `WEBAUTHN_RP_NAME` still have defaults in production, but deployments can override them to match their application boundary, retention policy, and brand.

## Reverse Proxies

Set `TRUST_PROXY=true` only when SceauID runs behind a trusted reverse proxy or platform load balancer that sets forwarded client headers.

When enabled, Fastify uses forwarded address headers to resolve `request.ip`. This matters for IP-scoped controls such as passkey ceremony rate limits.

Leave `TRUST_PROXY=false` for direct local development or deployments where untrusted clients can set forwarded headers themselves.

## WebAuthn Alignment

`APP_ORIGIN` and `WEBAUTHN_RP_ID` must match the browser origin and relying party domain used by the application.

For example:

```txt
APP_ORIGIN=https://app.example.com
WEBAUTHN_RP_ID=app.example.com
```

Do not include a scheme in `WEBAUTHN_RP_ID`.
