# Rate Limits

SceauID uses Redis-backed fixed-window rate limits for sensitive unauthenticated auth flows.

## Protected Endpoints

| Endpoint | Limit | Window | Scope |
| --- | ---: | ---: | --- |
| `POST /v1/passkeys/login/start` | 20 | 60 seconds | Client IP |
| `POST /v1/passkeys/registration/start` | 10 | 60 seconds | Client IP |

The client IP is hashed before it is used as part of the Redis key. The stored key is only used for throttling and does not need to reveal the raw address.

If SceauID runs behind a trusted reverse proxy, set `TRUST_PROXY=true` so IP-scoped limits use the forwarded client address instead of the proxy address. Keep it disabled when clients can set forwarded headers directly.

## Responses

When a request is accepted, SceauID includes rate-limit headers:

```txt
ratelimit-limit: 20
ratelimit-remaining: 19
ratelimit-reset: 1780315260
```

When a request exceeds the configured limit, SceauID returns:

```http
HTTP/1.1 429 Too Many Requests
retry-after: 60
```

```json
{
  "error": "rate_limited",
  "message": "Too many requests. Try again after the rate limit resets.",
  "resetAt": "2026-06-01T12:01:00.000Z"
}
```

## Design Notes

Passkey ceremony start endpoints can create short-lived challenge state and may call WebAuthn option generation. Rate limiting them gives the service an abuse-control floor without blocking valid finish requests that already require ceremony identifiers.

Recovery flows keep their own stricter user-scoped limits because recovery-code redemption has different risk and usability tradeoffs.
