# Session Cookies

SceauID issues browser session cookies after successful passkey login when cookie support is configured.

## Default Policy

Session cookies use:

```txt
HttpOnly
Path=/
SameSite=Lax
Secure in production
```

Logout and current-session revocation clear the cookie with the same path and security attributes. This keeps browser behavior consistent when replacing the active session cookie with an expired tombstone.

## Token Shape

The cookie value is the opaque session token returned by the session service. SceauID stores only the token hash in PostgreSQL, so the raw token is not persisted server-side.

The JSON login response also includes the token for SDKs, native clients, CLIs, and server-side integrations that cannot rely on browser cookies.

## Deployment Notes

Use the default `SameSite=Lax` policy for same-site product apps. If a deployment needs cross-site browser cookies, configure `SameSite=None` together with `Secure=true` and a trusted HTTPS origin.

Failed login attempts do not set a session cookie.
