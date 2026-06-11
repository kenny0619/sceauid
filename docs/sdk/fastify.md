# Fastify Integration

`@sceauid/fastify` wraps the TypeScript SDK as a Fastify plugin with route `preHandler`s for optional and required SceauID sessions.

## Install

```sh
pnpm add @sceauid/fastify @sceauid/sdk
```

Fastify is a peer dependency:

```sh
pnpm add fastify
```

## Configure

Register the plugin once during app setup.

```ts
import Fastify from "fastify";
import { sceauidFastify } from "@sceauid/fastify";

const app = Fastify();

await app.register(
  sceauidFastify({
    baseUrl: process.env.SCEAUID_API_URL ?? "http://localhost:4000"
  })
);
```

`apiUrl` is also accepted as an alias for `baseUrl`.

## Load Optional Sessions

Use `app.sceauid.currentSession` when a route can work for both anonymous and authenticated users.

```ts
import { getSceauIDCurrentSession } from "@sceauid/fastify";

app.get(
  "/account-preview",
  { preHandler: app.sceauid.currentSession },
  async (request) => {
    const currentSession = getSceauIDCurrentSession(request);

    return {
      signedIn: currentSession !== null,
      user: currentSession?.user ?? null
    };
  }
);
```

The preHandler calls SceauID with the incoming session cookie and attaches the result to:

- `request.sceauid.currentSession`
- `request.sceauidCurrentSession`

Use `getSceauIDCurrentSession(request)` instead of reading those properties directly.

## Require Sessions

Use `app.sceauid.requireCurrentSession` for protected routes.

```ts
app.get(
  "/settings",
  { preHandler: app.sceauid.requireCurrentSession },
  async (request) => {
    const currentSession = getSceauIDCurrentSession(request);

    return {
      user: currentSession?.user
    };
  }
);
```

If the request does not have a valid SceauID session, the preHandler responds with:

```json
{
  "error": "unauthenticated",
  "message": "SceauID session is required"
}
```

You can customize that response body:

```ts
await app.register(
  sceauidFastify({
    baseUrl: process.env.SCEAUID_API_URL,
    unauthorizedBody: {
      error: "login_required",
      message: "Sign in to continue"
    }
  })
);
```

## Direct Session Lookup

Call `app.sceauid.currentSessionFromRequest(request)` inside custom hooks or handlers when you need manual control.

```ts
app.post("/billing/portal", async (request, reply) => {
  const currentSession = await app.sceauid.currentSessionFromRequest(request);

  if (!currentSession) {
    return reply.status(401).send({ error: "unauthenticated" });
  }

  return {
    userId: currentSession.user.id
  };
});
```

## Standalone PreHandlers

If you do not want to register the plugin decorator, create preHandlers directly:

```ts
import { requireSceauIDCurrentSession } from "@sceauid/fastify";

const requireSession = requireSceauIDCurrentSession({
  baseUrl: process.env.SCEAUID_API_URL
});

app.get("/settings", { preHandler: requireSession }, async (request) => ({
  user: getSceauIDCurrentSession(request)?.user
}));
```

## Cookie Names

The default session cookie is `sceauid_session`. If your deployment uses a different cookie name, configure it once:

```ts
await app.register(
  sceauidFastify({
    baseUrl: process.env.SCEAUID_API_URL,
    sessionCookieName: "identity_session"
  })
);
```

`cookieName` is accepted as a shorter alias.

## Custom Fetch

Pass a custom `fetch` implementation for tests, tracing, or non-standard runtimes:

```ts
await app.register(
  sceauidFastify({
    baseUrl: "https://identity.example.com",
    fetch: instrumentedFetch
  })
);
```
