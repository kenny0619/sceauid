# Passkey API

SceauID exposes passkey registration and login as explicit two-step ceremonies:

1. Start the ceremony and receive WebAuthn public options.
2. Ask the browser or native platform authenticator to create or get a credential.
3. Finish the ceremony by sending the authenticator result back to SceauID.

The API owns challenge storage, credential verification, session creation, and security event recording. Product applications own the user experience around those steps.

## Registration Flow

```mermaid
sequenceDiagram
    participant App as Product App
    participant API as SceauID API
    participant Authenticator as Browser / Authenticator

    App->>API: POST /v1/passkeys/registration/start
    API-->>App: registrationId, expiresAt, publicKey options
    App->>Authenticator: navigator.credentials.create(options)
    Authenticator-->>App: attestation credential
    App->>API: POST /v1/passkeys/registration/finish
    API-->>App: userId, credential
```

### Start Registration

`POST /v1/passkeys/registration/start`

```json
{
  "userId": "user_123",
  "userName": "ibukunoluwa@example.com",
  "userDisplayName": "Ibukunoluwa Kehinde"
}
```

Response:

```json
{
  "registrationId": "registration_123",
  "expiresAt": "2026-06-04T12:05:00.000Z",
  "options": {}
}
```

`options` is the public key credential creation payload that should be passed to the browser after converting WebAuthn binary fields into the format expected by the client runtime.

### Finish Registration

`POST /v1/passkeys/registration/finish`

```json
{
  "registrationId": "registration_123",
  "credential": {
    "id": "credential_public_id",
    "rawId": "credential_raw_id",
    "response": {
      "clientDataJSON": "base64url_client_data",
      "attestationObject": "base64url_attestation_object"
    },
    "clientExtensionResults": {},
    "type": "public-key"
  },
  "deviceName": "MacBook Pro"
}
```

Response:

```json
{
  "userId": "user_123",
  "credential": {
    "id": "passkey_123",
    "credentialId": "credential_public_id",
    "deviceName": "MacBook Pro",
    "createdAt": "2026-06-04T12:00:00.000Z"
  }
}
```

## Login Flow

```mermaid
sequenceDiagram
    participant App as Product App
    participant API as SceauID API
    participant Authenticator as Browser / Authenticator

    App->>API: POST /v1/passkeys/login/start
    API-->>App: loginId, expiresAt, publicKey options
    App->>Authenticator: navigator.credentials.get(options)
    Authenticator-->>App: assertion credential
    App->>API: POST /v1/passkeys/login/finish
    API-->>App: userId, credential, session
    API-->>App: Set-Cookie: sceauid_session=...
```

### Start Login

`POST /v1/passkeys/login/start`

For account-scoped login:

```json
{
  "userId": "user_123"
}
```

For discoverable credential login, send an empty object:

```json
{}
```

Response:

```json
{
  "loginId": "login_123",
  "expiresAt": "2026-06-04T12:05:00.000Z",
  "options": {}
}
```

### Finish Login

`POST /v1/passkeys/login/finish`

```json
{
  "loginId": "login_123",
  "credential": {
    "id": "credential_public_id",
    "rawId": "credential_raw_id",
    "response": {
      "clientDataJSON": "base64url_client_data",
      "authenticatorData": "base64url_authenticator_data",
      "signature": "base64url_signature",
      "userHandle": "base64url_user_handle"
    },
    "clientExtensionResults": {},
    "type": "public-key"
  },
  "deviceLabel": "Safari on macOS"
}
```

Response:

```json
{
  "userId": "user_123",
  "credential": {
    "id": "passkey_123",
    "credentialId": "credential_public_id",
    "signCount": 8,
    "lastUsedAt": "2026-06-04T12:00:00.000Z"
  },
  "session": {
    "id": "session_123",
    "token": "session_token",
    "expiresAt": "2026-07-04T12:00:00.000Z"
  }
}
```

On successful login, the API also sets an HTTP-only session cookie. The cookie name is configured with `SESSION_COOKIE_NAME`.

The JSON `session.token` is kept for SDKs, native apps, CLIs, and server-side integrations that cannot rely on browser cookies.

## Session Cookie Behavior

The default cookie behavior is:

- `HttpOnly`
- `Path=/`
- `SameSite=Lax`
- `Secure` in production

Failed login attempts do not set a session cookie.

## Error Shape

Client errors use a consistent JSON shape:

```json
{
  "error": "login_finish_failed",
  "message": "Passkey login verification failed"
}
```

Current passkey route error codes:

- `invalid_request`
- `registration_start_failed`
- `registration_finish_failed`
- `login_start_failed`
- `login_finish_failed`

## Security Events

Passkey flows record security events as product data, not only server logs.

Current events include:

- `passkey_registration_started`
- `passkey_registered`
- `passkey_registration_failed`
- `login_started`
- `login_succeeded`
- `login_failed`

These events are intended to support account timelines, user-facing security history, investigation workflows, and future webhook delivery.

## Integration Notes

- Challenge IDs (`registrationId` and `loginId`) are short-lived and single-use.
- WebAuthn binary values should be encoded as base64url strings over HTTP.
- The API validates the relying party ID and origin during finish calls.
- Sessions are server-side records and can be revoked independently of the cookie.
- Browser clients should call the SDK or API with credentials enabled so cookies are sent and received.
