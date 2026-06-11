# Express Integration

`@sceauid/express` wraps the TypeScript SDK for Express applications that need to read or require SceauID sessions from incoming requests.

## Install

```sh
pnpm add @sceauid/express @sceauid/sdk
```

Express is a peer dependency:

```sh
pnpm add express
```

## Configure

Create the integration once and reuse its middleware.

```ts
import express from "express";
import { createSceauIDExpress } from "@sceauid/express";

const app = express();
const sceauid = createSceauIDExpress({
  baseUrl: process.env.SCEAUID_API_URL ?? "http://localhost:4000"
});
```

`apiUrl` is also accepted as an alias for `baseUrl`.

## Load Optional Sessions

Use `currentSession` when a route can work for both anonymous and authenticated users.

```ts
import { getSceauIDCurrentSession } from "@sceauid/express";

app.get("/account-preview", sceauid.currentSession, (req, res) => {
  const currentSession = getSceauIDCurrentSession(req);

  res.json({
    signedIn: currentSession !== null,
    user: currentSession?.user ?? null
  });
});
```

The middleware calls SceauID with the incoming session cookie and attaches the result to:

- `req.sceauid.currentSession`
- `req.sceauidCurrentSession`

Use `getSceauIDCurrentSession(req)` instead of reading those properties directly.

## Require Sessions

Use `requireCurrentSession` for protected routes.

```ts
app.get("/settings", sceauid.requireCurrentSession, (req, res) => {
  const currentSession = getSceauIDCurrentSession(req);

  res.json({
    user: currentSession?.user
  });
});
```

If the request does not have a valid SceauID session, the middleware responds with:

```json
{
  "error": "unauthenticated",
  "message": "SceauID session is required"
}
```

You can customize that response body:

```ts
const sceauid = createSceauIDExpress({
  baseUrl: process.env.SCEAUID_API_URL,
  unauthorizedBody: {
    error: "login_required",
    message: "Sign in to continue"
  }
});
```

## Direct Session Lookup

Call `currentSessionFromRequest(req)` inside custom middleware or route handlers when you need manual control.

```ts
app.post("/billing/portal", async (req, res, next) => {
  try {
    const currentSession = await sceauid.currentSessionFromRequest(req);

    if (!currentSession) {
      res.status(401).json({ error: "unauthenticated" });
      return;
    }

    res.json({
      userId: currentSession.user.id
    });
  } catch (error) {
    next(error);
  }
});
```

## Cookie Names

The default session cookie is `sceauid_session`. If your deployment uses a different cookie name, configure it once:

```ts
const sceauid = createSceauIDExpress({
  baseUrl: process.env.SCEAUID_API_URL,
  sessionCookieName: "identity_session"
});
```

`cookieName` is accepted as a shorter alias.

## Custom Fetch

Pass a custom `fetch` implementation for tests, tracing, or non-standard runtimes:

```ts
const sceauid = createSceauIDExpress({
  baseUrl: "https://identity.example.com",
  fetch: instrumentedFetch
});
```
