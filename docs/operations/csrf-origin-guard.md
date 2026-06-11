# CSRF Origin Guard

SceauID protects cookie-authenticated state changes with a trusted origin guard.

The guard only applies when all of these are true:

- The HTTP method is unsafe: `POST`, `PUT`, `PATCH`, or `DELETE`.
- The request includes the configured SceauID session cookie.
- The request is handled by the API service.

When those conditions are met, the request must include an `Origin` header matching `APP_ORIGIN`.

## Why It Exists

CORS controls which browser origins can read responses. It is not, by itself, a complete CSRF defense for cookie-authenticated state changes.

The origin guard rejects cross-site attempts to use a user's SceauID session cookie against mutation endpoints.

## Rejected Requests

Requests with a missing or untrusted origin return `403`:

```json
{
  "error": "csrf_origin_rejected",
  "message": "Request origin is not trusted"
}
```

## Non-Browser Integrations

Requests without the SceauID session cookie are not blocked by the guard. This keeps server-side and token-based integrations possible while protecting browser cookie flows.

If a server-side integration intentionally sends the session cookie for unsafe methods, it should also send the trusted `Origin` header.
