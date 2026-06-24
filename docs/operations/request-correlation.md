# Request Correlation

SceauID attaches a request ID to every API response.

```txt
x-request-id: req_abc123
```

If a client sends `x-request-id`, SceauID reuses it. Otherwise, Fastify generates one for the request. The same ID is available in server logs, which lets operators connect a client-facing failure to internal diagnostics without exposing stack traces or dependency details.

Authentication and recovery security events also include the request ID as `context.traceId` when request context is available. SceauID records `context.userAgent` and a hashed `context.ipHash` so operators can investigate auth activity without storing raw client IP addresses in the security-event timeline.

Security-event list endpoints accept `createdAfter` and `createdBefore` ISO timestamp filters. Use them with `context.traceId` when reviewing a specific incident window.

## Error Responses

Unexpected server errors return a generic `500` response:

```json
{
  "error": "internal_server_error",
  "message": "Unexpected server error",
  "requestId": "req_abc123"
}
```

The raw error is logged server-side with the same request ID.

Validation and client-side framework errors keep their client-facing message but still include the request ID:

```json
{
  "error": "request_failed",
  "message": "querystring must have required property 'email'",
  "requestId": "req_abc123"
}
```

Application-level auth and identity errors returned directly by route handlers keep their existing response shape.
