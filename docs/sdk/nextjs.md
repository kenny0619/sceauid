# Next.js Integration

`@sceauid/nextjs` wraps the TypeScript SDK for App Router server code, route handlers, and middleware.

## Install

```sh
pnpm add @sceauid/nextjs @sceauid/sdk
```

Next.js is a peer dependency:

```sh
pnpm add next
```

## Configure

Create the integration in a server-only module and reuse it across route handlers, layouts, and middleware.

```ts
import { createSceauIDNext } from "@sceauid/nextjs";

export const sceauid = createSceauIDNext({
  baseUrl: process.env.SCEAUID_API_URL ?? "http://localhost:4000"
});
```

`apiUrl` is also accepted as an alias for `baseUrl`.

## Server Components

Use `currentSessionFromCookies(cookies())` in App Router server components.

```tsx
import { cookies } from "next/headers";
import { sceauid } from "@/lib/sceauid";

export default async function AccountPage() {
  const currentSession = await sceauid.currentSessionFromCookies(cookies());

  return <pre>{JSON.stringify(currentSession?.user ?? null, null, 2)}</pre>;
}
```

The helper accepts both synchronous and promise-based cookie stores, so it works with modern Next.js `cookies()` behavior.

## Route Handlers

Use `currentSessionFromRequest(request)` in route handlers.

```ts
import type { NextRequest } from "next/server";
import { sceauid } from "@/lib/sceauid";

export async function GET(request: NextRequest) {
  const currentSession = await sceauid.currentSessionFromRequest(request);

  if (!currentSession) {
    return sceauid.unauthorizedResponse();
  }

  return Response.json({
    user: currentSession.user
  });
}
```

## Middleware

Use `createSceauIDMiddleware` directly, or use the integration's `middleware()` helper.

```ts
import { sceauid } from "@/lib/sceauid";

export default sceauid.middleware({
  publicPaths: ["/login", "/signup", /^\/public/],
  loginPath: "/login",
  redirectToLogin: true
});

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"]
};
```

When the request is authenticated, the middleware returns `undefined` so Next.js can continue to the matched route. When the request is unauthenticated, it returns either a JSON `401` response or a redirect response, depending on your configuration.

## Unauthorized Responses

By default, unauthenticated route handlers and middleware return:

```json
{
  "error": "unauthenticated",
  "message": "SceauID session is required"
}
```

You can customize the body:

```ts
export const sceauid = createSceauIDNext({
  baseUrl: process.env.SCEAUID_API_URL,
  unauthorizedBody: {
    error: "login_required",
    message: "Sign in to continue"
  }
});
```

## Cookie Names

The default session cookie is `sceauid_session`. If your deployment uses a different cookie name, configure it once:

```ts
export const sceauid = createSceauIDNext({
  baseUrl: process.env.SCEAUID_API_URL,
  sessionCookieName: "identity_session"
});
```

`cookieName` is accepted as a shorter alias.

## Custom Fetch

Pass a custom `fetch` implementation for tests, tracing, or non-standard runtimes:

```ts
export const sceauid = createSceauIDNext({
  baseUrl: "https://identity.example.com",
  fetch: instrumentedFetch
});
```
