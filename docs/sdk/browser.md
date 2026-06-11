# Browser SDK

The browser SDK wraps SceauID's two-step WebAuthn API with `@simplewebauthn/browser` so product frontends do not need to manually call `navigator.credentials.create()` or `navigator.credentials.get()`.

Use `SceauIDClient` when you want low-level HTTP methods. Use `SceauIDBrowserClient` when a browser should perform passkey ceremonies.

## Setup

```ts
import { SceauIDBrowserClient } from "@sceauid/sdk";

const sceau = new SceauIDBrowserClient({
  baseUrl: "https://identity.example.com"
});
```

The SDK sends requests with `credentials: "include"` so SceauID's HTTP-only session cookie is available to browser flows. Configure CORS and cookie settings on the API for the product app origin.

## Register A Passkey

```ts
await sceau.registerPasskey({
  userId: "user_123",
  userName: "ibukunoluwa@example.com",
  userDisplayName: "Ibukunoluwa Kehinde",
  deviceName: "MacBook Pro"
});
```

This helper:

1. calls `POST /v1/passkeys/registration/start`
2. passes the returned WebAuthn options to the browser authenticator
3. calls `POST /v1/passkeys/registration/finish` with the attestation response

## Login With A Passkey

```ts
await sceau.loginWithPasskey({
  userId: "user_123",
  deviceLabel: "Safari on macOS"
});
```

For discoverable credential login, omit `userId`:

```ts
await sceau.loginWithPasskey({
  deviceLabel: "Safari on macOS"
});
```

For browser autofill or conditional UI:

```ts
await sceau.loginWithPasskey({
  useBrowserAutofill: true
});
```

Successful browser login sets the SceauID session cookie when the API is configured with cookie support.

## Register A Recovery Passkey

After a recovery request is completed, SceauID returns a short-lived recovery session token. Use that token only for the recovery passkey handoff:

```ts
await sceau.registerRecoveryPasskey({
  recoverySessionToken: "recovery_session_token",
  userName: "ibukunoluwa@example.com",
  userDisplayName: "Ibukunoluwa Kehinde",
  deviceName: "iPhone"
});
```

This helper starts a recovery-scoped registration ceremony and finishes it through the normal registration finish endpoint. The API validates that the challenge belongs to the recovery flow before finalizing recovery state.

## Lower-Level Methods

The browser client extends `SceauIDClient`, so the raw API methods are still available:

```ts
const start = await sceau.startPasskeyLogin({ userId: "user_123" });
const events = await sceau.recoveryEvents({ limit: 20 });
const session = await sceau.currentSession();
```

Use lower-level methods when building custom native, server-side, or test harness flows that cannot use browser WebAuthn APIs directly.
