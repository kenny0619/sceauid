import { describe, expect, it } from "vitest";
import {
  SceauIDBrowserClient,
  SceauIDClient,
  SceauIDError,
  type SceauIDFetchInit,
  type WebAuthnAuthenticationCredential,
  type WebAuthnAuthenticationOptions,
  type WebAuthnRegistrationCredential,
  type WebAuthnRegistrationOptions
} from "./index.js";

type FetchCall = {
  init?: SceauIDFetchInit;
  url: string;
};

function createFetchStub(responseBody: unknown, options: { ok?: boolean; status?: number } = {}) {
  const calls: FetchCall[] = [];

  const fetch = async (url: string, init?: SceauIDFetchInit) => {
    calls.push({ init, url });

    return {
      ok: options.ok ?? true,
      status: options.status ?? 200,
      json: async () => responseBody
    };
  };

  return { calls, fetch };
}

function createFetchSequenceStub(
  responses: Array<{ body: unknown; ok?: boolean; status?: number }>
) {
  const calls: FetchCall[] = [];

  const fetch = async (url: string, init?: SceauIDFetchInit) => {
    calls.push({ init, url });

    const response = responses.shift();

    if (!response) {
      throw new Error(`Unexpected SDK fetch call to ${url}`);
    }

    return {
      ok: response.ok ?? true,
      status: response.status ?? 200,
      json: async () => response.body
    };
  };

  return { calls, fetch };
}

function expectJsonRequestBody(call: FetchCall, expectedBody: unknown) {
  expect(call.init?.body).toBeTypeOf("string");
  expect(JSON.parse(call.init?.body ?? "{}")).toEqual(expectedBody);
}

describe("SceauIDClient", () => {
  it("starts passkey registration with the expected request", async () => {
    const { calls, fetch } = createFetchStub({
      expiresAt: "2026-06-04T00:00:00.000Z",
      options: { challenge: "challenge" },
      registrationId: "registration_123"
    });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com/",
      fetch
    });

    const result = await client.startPasskeyRegistration({
      userDisplayName: "Ibukunoluwa Kehinde",
      userId: "user_123",
      userName: "ibukunoluwa"
    });

    expect(result.registrationId).toBe("registration_123");
    expect(calls).toEqual([
      {
        init: {
          body: JSON.stringify({
            userDisplayName: "Ibukunoluwa Kehinde",
            userId: "user_123",
            userName: "ibukunoluwa"
          }),
          credentials: "include",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json"
          },
          method: "POST"
        },
        url: "https://identity.example.com/v1/passkeys/registration/start"
      }
    ]);
  });

  it("finishes passkey login and returns the session response", async () => {
    const { calls, fetch } = createFetchStub({
      credential: {
        credentialId: "credential_public_id",
        id: "credential_123",
        lastUsedAt: "2026-06-04T00:00:00.000Z",
        signCount: 5
      },
      session: {
        expiresAt: "2026-06-05T00:00:00.000Z",
        id: "session_123",
        token: "session_token"
      },
      userId: "user_123"
    });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const result = await client.finishPasskeyLogin({
      credential: {
        clientExtensionResults: {},
        id: "credential_public_id",
        rawId: "credential_raw_id",
        response: {
          authenticatorData: "authenticator_data",
          clientDataJSON: "client_data_json",
          signature: "signature"
        },
        type: "public-key"
      },
      loginId: "login_123"
    });

    expect(result.session.token).toBe("session_token");
    expect(calls[0]).toMatchObject({
      init: {
        credentials: "include",
        method: "POST"
      },
      url: "https://identity.example.com/v1/passkeys/login/finish"
    });
  });

  it("fetches the current session with credentials", async () => {
    const { calls, fetch } = createFetchStub({
      user: {
        id: "user_123",
        displayName: "Test User",
        status: "active"
      },
      session: {
        id: "session_123",
        kind: "standard",
        deviceLabel: "Safari on macOS",
        userAgent: "test-agent",
        expiresAt: "2026-07-04T12:00:00.000Z",
        authenticatedAt: "2026-06-04T11:55:00.000Z",
        createdAt: "2026-06-04T12:00:00.000Z"
      }
    });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const result = await client.currentSession();

    expect(result.user.id).toBe("user_123");
    expect(result.session.kind).toBe("standard");
    expect(calls).toEqual([
      {
        init: {
          body: undefined,
          credentials: "include",
          headers: {
            Accept: "application/json"
          },
          method: "GET"
        },
        url: "https://identity.example.com/v1/sessions/current"
      }
    ]);
  });

  it("lists sessions with credentials", async () => {
    const { calls, fetch } = createFetchStub({
      sessions: [
        {
          id: "session_123",
          current: true,
          kind: "standard",
          deviceLabel: "Safari on macOS",
          userAgent: "test-agent",
          expiresAt: "2026-07-04T12:00:00.000Z",
          revokedAt: null,
          authenticatedAt: "2026-06-04T11:55:00.000Z",
          createdAt: "2026-06-04T12:00:00.000Z"
        },
        {
          id: "recovery_session_123",
          current: false,
          kind: "recovery",
          deviceLabel: "Recovery session",
          userAgent: null,
          expiresAt: "2026-06-04T12:15:00.000Z",
          revokedAt: null,
          authenticatedAt: "2026-06-04T12:00:00.000Z",
          createdAt: "2026-06-04T12:00:00.000Z"
        }
      ]
    });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const result = await client.sessions();

    expect(result.sessions.map((session) => session.kind)).toEqual(["standard", "recovery"]);
    expect(calls).toEqual([
      {
        init: {
          body: undefined,
          credentials: "include",
          headers: {
            Accept: "application/json"
          },
          method: "GET"
        },
        url: "https://identity.example.com/v1/sessions"
      }
    ]);
  });

  it("logs out the current session with credentials", async () => {
    const { calls, fetch } = createFetchStub({ ok: true });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const result = await client.logout();

    expect(result).toEqual({ ok: true });
    expect(calls).toEqual([
      {
        init: {
          body: undefined,
          credentials: "include",
          headers: {
            Accept: "application/json"
          },
          method: "DELETE"
        },
        url: "https://identity.example.com/v1/sessions/current"
      }
    ]);
  });

  it("revokes a session with credentials", async () => {
    const { calls, fetch } = createFetchStub({ ok: true });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const result = await client.revokeSession("session/123");

    expect(result).toEqual({ ok: true });
    expect(calls).toEqual([
      {
        init: {
          body: undefined,
          credentials: "include",
          headers: {
            Accept: "application/json"
          },
          method: "DELETE"
        },
        url: "https://identity.example.com/v1/sessions/session%2F123"
      }
    ]);
  });

  it("lists security events with credentials", async () => {
    const { calls, fetch } = createFetchStub({
      events: [
        {
          id: "event_123",
          userId: "user_123",
          actorUserId: "user_123",
          sessionId: "session_123",
          eventType: "session_revoked",
          outcome: "success",
          riskLevel: "low",
          metadata: {
            reason: "targeted_revoke"
          },
          context: {},
          createdAt: "2026-06-04T12:00:00.000Z"
        }
      ],
      nextCursor: "next-page-token"
    });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const result = await client.securityEvents({
      cursor: "current-page-token",
      eventTypes: ["login_failed", "session_revoked"],
      outcomes: ["failure"],
      riskLevels: ["medium", "high"],
      createdAfter: new Date("2026-06-01T00:00:00.000Z"),
      createdBefore: "2026-06-02T00:00:00.000Z",
      limit: 10
    });

    expect(result.events).toHaveLength(1);
    expect(result.nextCursor).toBe("next-page-token");
    expect(calls).toEqual([
      {
        init: {
          body: undefined,
          credentials: "include",
          headers: {
            Accept: "application/json"
          },
          method: "GET"
        },
        url: "https://identity.example.com/v1/security-events?limit=10&cursor=current-page-token&eventType=login_failed&eventType=session_revoked&outcome=failure&riskLevel=medium&riskLevel=high&createdAfter=2026-06-01T00%3A00%3A00.000Z&createdBefore=2026-06-02T00%3A00%3A00.000Z"
      }
    ]);
  });

  it("gets a security event with credentials", async () => {
    const { calls, fetch } = createFetchStub({
      event: {
        id: "event_123",
        userId: "user_123",
        actorUserId: "user_123",
        sessionId: "session_123",
        eventType: "session_revoked",
        outcome: "success",
        riskLevel: "low",
        metadata: {
          reason: "targeted_revoke"
        },
        context: {},
        createdAt: "2026-06-04T12:00:00.000Z"
      }
    });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const result = await client.securityEvent("event/123");

    expect(result.event.id).toBe("event_123");
    expect(calls).toEqual([
      {
        init: {
          body: undefined,
          credentials: "include",
          headers: {
            Accept: "application/json"
          },
          method: "GET"
        },
        url: "https://identity.example.com/v1/security-events/event%2F123"
      }
    ]);
  });

  it("lists recovery events with credentials", async () => {
    const { calls, fetch } = createFetchStub({
      events: [
        {
          id: "event_123",
          userId: "user_123",
          actorUserId: "user_123",
          sessionId: "recovery_session_123",
          eventType: "recovery_code_redeemed",
          outcome: "success",
          riskLevel: "medium",
          metadata: {
            redeemedAt: "2026-06-04T12:00:00.000Z"
          },
          context: {},
          createdAt: "2026-06-04T12:00:00.000Z"
        }
      ],
      nextCursor: null
    });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const result = await client.recoveryEvents({
      cursor: "current-page-token",
      outcomes: ["success"],
      riskLevels: ["medium"],
      createdAfter: "2026-06-01T00:00:00.000Z",
      createdBefore: new Date("2026-06-02T00:00:00.000Z"),
      limit: 10
    });

    expect(result.events[0]?.eventType).toBe("recovery_code_redeemed");
    expect(calls).toEqual([
      {
        init: {
          body: undefined,
          credentials: "include",
          headers: {
            Accept: "application/json"
          },
          method: "GET"
        },
        url: "https://identity.example.com/v1/recovery/events?limit=10&cursor=current-page-token&outcome=success&riskLevel=medium&createdAfter=2026-06-01T00%3A00%3A00.000Z&createdBefore=2026-06-02T00%3A00%3A00.000Z"
      }
    ]);
  });

  it("lists passkeys with credentials", async () => {
    const { calls, fetch } = createFetchStub({
      passkeys: [
        {
          id: "passkey_123",
          credentialId: "credential_public_id",
          deviceName: "MacBook Pro",
          signCount: 8,
          lastUsedAt: "2026-06-04T12:00:00.000Z",
          createdAt: "2026-06-01T12:00:00.000Z",
          revokedAt: null
        }
      ]
    });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const result = await client.passkeys();

    expect(result.passkeys).toHaveLength(1);
    expect(calls).toEqual([
      {
        init: {
          body: undefined,
          credentials: "include",
          headers: {
            Accept: "application/json"
          },
          method: "GET"
        },
        url: "https://identity.example.com/v1/passkeys"
      }
    ]);
  });

  it("revokes a passkey with credentials", async () => {
    const { calls, fetch } = createFetchStub({ ok: true });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const result = await client.revokePasskey("passkey/123");

    expect(result).toEqual({ ok: true });
    expect(calls).toEqual([
      {
        init: {
          body: undefined,
          credentials: "include",
          headers: {
            Accept: "application/json"
          },
          method: "DELETE"
        },
        url: "https://identity.example.com/v1/passkeys/passkey%2F123"
      }
    ]);
  });

  it("fetches recovery code status with credentials", async () => {
    const { calls, fetch } = createFetchStub({
      recoveryCodesConfigured: true,
      unusedRecoveryCodeCount: 8
    });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const result = await client.recoveryCodeStatus();

    expect(result.unusedRecoveryCodeCount).toBe(8);
    expect(calls).toEqual([
      {
        init: {
          body: undefined,
          credentials: "include",
          headers: {
            Accept: "application/json"
          },
          method: "GET"
        },
        url: "https://identity.example.com/v1/recovery/status"
      }
    ]);
  });

  it("enrolls recovery codes with credentials", async () => {
    const { calls, fetch } = createFetchStub({
      codes: ["ABCDE-FGHIJ-KLMNO-PQRST"],
      recoveryCodesConfigured: true,
      unusedRecoveryCodeCount: 1
    });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const result = await client.enrollRecoveryCodes();

    expect(result.codes).toEqual(["ABCDE-FGHIJ-KLMNO-PQRST"]);
    expect(calls).toEqual([
      {
        init: {
          body: undefined,
          credentials: "include",
          headers: {
            Accept: "application/json"
          },
          method: "POST"
        },
        url: "https://identity.example.com/v1/recovery/codes"
      }
    ]);
  });

  it("redeems a recovery code", async () => {
    const { calls, fetch } = createFetchStub({
      ok: true,
      recoveryRequest: {
        id: "recovery_request_123",
        expiresAt: "2026-06-01T12:15:00.000Z",
        riskLevel: "medium"
      }
    });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const result = await client.redeemRecoveryCode({
      code: "ABCDE-FGHIJ-KLMNO-PQRST",
      userId: "user_123"
    });

    expect(result).toEqual({
      ok: true,
      recoveryRequest: {
        id: "recovery_request_123",
        expiresAt: "2026-06-01T12:15:00.000Z",
        riskLevel: "medium"
      }
    });
    expect(calls).toEqual([
      {
        init: {
          body: JSON.stringify({
            code: "ABCDE-FGHIJ-KLMNO-PQRST",
            userId: "user_123"
          }),
          credentials: "include",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json"
          },
          method: "POST"
        },
        url: "https://identity.example.com/v1/recovery/codes/redeem"
      }
    ]);
  });

  it("fetches recovery request status", async () => {
    const { calls, fetch } = createFetchStub({
      recoveryRequest: {
        id: "recovery/request/123",
        active: true,
        expiresAt: "2026-06-01T12:15:00.000Z",
        riskLevel: "medium",
        status: "pending"
      }
    });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const result = await client.recoveryRequestStatus("recovery/request/123");

    expect(result.recoveryRequest.active).toBe(true);
    expect(calls).toEqual([
      {
        init: {
          body: undefined,
          credentials: "include",
          headers: {
            Accept: "application/json"
          },
          method: "GET"
        },
        url: "https://identity.example.com/v1/recovery/requests/recovery%2Frequest%2F123"
      }
    ]);
  });

  it("completes a recovery request", async () => {
    const { calls, fetch } = createFetchStub({
      ok: true,
      recoverySession: {
        id: "recovery_session_123",
        token: "recovery_session_token",
        expiresAt: "2026-06-01T12:16:00.000Z"
      },
      recoveryRequest: {
        id: "recovery/request/123",
        completedAt: "2026-06-01T12:01:00.000Z",
        status: "completed"
      }
    });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const result = await client.completeRecoveryRequest("recovery/request/123");

    expect(result.recoverySession.token).toBe("recovery_session_token");
    expect(result.recoveryRequest.status).toBe("completed");
    expect(calls).toEqual([
      {
        init: {
          body: undefined,
          credentials: "include",
          headers: {
            Accept: "application/json"
          },
          method: "POST"
        },
        url: "https://identity.example.com/v1/recovery/requests/recovery%2Frequest%2F123/complete"
      }
    ]);
  });

  it("cancels a recovery request", async () => {
    const { calls, fetch } = createFetchStub({
      ok: true,
      recoveryRequest: {
        id: "recovery/request/123",
        cancelledAt: "2026-06-01T12:02:00.000Z",
        status: "cancelled"
      }
    });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const result = await client.cancelRecoveryRequest("recovery/request/123");

    expect(result.recoveryRequest.status).toBe("cancelled");
    expect(calls).toEqual([
      {
        init: {
          body: undefined,
          credentials: "include",
          headers: {
            Accept: "application/json"
          },
          method: "DELETE"
        },
        url: "https://identity.example.com/v1/recovery/requests/recovery%2Frequest%2F123"
      }
    ]);
  });

  it("starts recovery passkey registration", async () => {
    const { calls, fetch } = createFetchStub({
      registrationId: "registration_123",
      expiresAt: "2026-06-01T12:05:00.000Z",
      options: {
        challenge: "challenge"
      }
    });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const result = await client.startRecoveryPasskeyRegistration({
      recoverySessionToken: "recovery_session_token",
      userName: "ibukunoluwa@example.com",
      userDisplayName: "Ibukunoluwa Kehinde"
    });

    expect(result.registrationId).toBe("registration_123");
    expect(calls).toEqual([
      {
        init: {
          body: JSON.stringify({
            recoverySessionToken: "recovery_session_token",
            userName: "ibukunoluwa@example.com",
            userDisplayName: "Ibukunoluwa Kehinde"
          }),
          credentials: "include",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json"
          },
          method: "POST"
        },
        url: "https://identity.example.com/v1/recovery/passkeys/registration/start"
      }
    ]);
  });

  it("registers a passkey through the browser ceremony", async () => {
    const registrationOptions: WebAuthnRegistrationOptions = {
      challenge: "registration_challenge",
      pubKeyCredParams: [{ alg: -7, type: "public-key" }],
      rp: {
        id: "identity.example.com",
        name: "SceauID"
      },
      user: {
        displayName: "Ibukunoluwa Kehinde",
        id: "user_123",
        name: "ibukunoluwa@example.com"
      }
    };
    const registrationCredential: WebAuthnRegistrationCredential = {
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      id: "credential_public_id",
      rawId: "credential_raw_id",
      response: {
        attestationObject: "attestation_object",
        clientDataJSON: "client_data_json",
        transports: ["internal"]
      },
      type: "public-key"
    };
    const ceremonyCalls: unknown[] = [];
    const { calls, fetch } = createFetchSequenceStub([
      {
        body: {
          expiresAt: "2026-06-04T00:05:00.000Z",
          options: registrationOptions,
          registrationId: "registration_123"
        }
      },
      {
        body: {
          credential: {
            createdAt: "2026-06-04T00:01:00.000Z",
            credentialId: "credential_public_id",
            deviceName: "MacBook Pro",
            id: "passkey_123"
          },
          userId: "user_123"
        }
      }
    ]);
    const client = new SceauIDBrowserClient({
      baseUrl: "https://identity.example.com",
      ceremonies: {
        startRegistration: async (options) => {
          ceremonyCalls.push(options);
          return registrationCredential;
        }
      },
      fetch
    });

    const result = await client.registerPasskey({
      deviceName: "MacBook Pro",
      useAutoRegister: true,
      userDisplayName: "Ibukunoluwa Kehinde",
      userId: "user_123",
      userName: "ibukunoluwa@example.com"
    });

    expect(result.credential.deviceName).toBe("MacBook Pro");
    expect(ceremonyCalls).toEqual([
      {
        optionsJSON: registrationOptions,
        useAutoRegister: true
      }
    ]);
    expect(calls).toHaveLength(2);
    expect(calls[0]).toMatchObject({
      init: {
        credentials: "include",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json"
        },
        method: "POST"
      },
      url: "https://identity.example.com/v1/passkeys/registration/start"
    });
    expectJsonRequestBody(calls[0], {
      userDisplayName: "Ibukunoluwa Kehinde",
      userId: "user_123",
      userName: "ibukunoluwa@example.com"
    });
    expect(calls[1]).toMatchObject({
      init: {
        credentials: "include",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json"
        },
        method: "POST"
      },
      url: "https://identity.example.com/v1/passkeys/registration/finish"
    });
    expectJsonRequestBody(calls[1], {
      credential: {
        authenticatorAttachment: "platform",
        clientExtensionResults: {},
        id: "credential_public_id",
        rawId: "credential_raw_id",
        response: {
          attestationObject: "attestation_object",
          clientDataJSON: "client_data_json",
          transports: ["internal"]
        },
        type: "public-key"
      },
      deviceName: "MacBook Pro",
      registrationId: "registration_123"
    });
  });

  it("logs in with a passkey through the browser ceremony", async () => {
    const authenticationOptions: WebAuthnAuthenticationOptions = {
      allowCredentials: [{ id: "credential_public_id", type: "public-key" }],
      challenge: "login_challenge",
      rpId: "identity.example.com"
    };
    const authenticationCredential: WebAuthnAuthenticationCredential = {
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      id: "credential_public_id",
      rawId: "credential_raw_id",
      response: {
        authenticatorData: "authenticator_data",
        clientDataJSON: "client_data_json",
        signature: "signature",
        userHandle: "user_handle"
      },
      type: "public-key"
    };
    const ceremonyCalls: unknown[] = [];
    const { calls, fetch } = createFetchSequenceStub([
      {
        body: {
          expiresAt: "2026-06-04T00:05:00.000Z",
          loginId: "login_123",
          options: authenticationOptions
        }
      },
      {
        body: {
          credential: {
            credentialId: "credential_public_id",
            id: "passkey_123",
            lastUsedAt: "2026-06-04T00:01:00.000Z",
            signCount: 9
          },
          session: {
            expiresAt: "2026-06-05T00:00:00.000Z",
            id: "session_123",
            token: "session_token"
          },
          userId: "user_123"
        }
      }
    ]);
    const client = new SceauIDBrowserClient({
      baseUrl: "https://identity.example.com",
      ceremonies: {
        startAuthentication: async (options) => {
          ceremonyCalls.push(options);
          return authenticationCredential;
        }
      },
      fetch
    });

    const result = await client.loginWithPasskey({
      deviceLabel: "Safari on macOS",
      useBrowserAutofill: true,
      userId: "user_123",
      verifyBrowserAutofillInput: false
    });

    expect(result.session.token).toBe("session_token");
    expect(ceremonyCalls).toEqual([
      {
        optionsJSON: authenticationOptions,
        useBrowserAutofill: true,
        verifyBrowserAutofillInput: false
      }
    ]);
    expect(calls).toHaveLength(2);
    expect(calls[0]).toMatchObject({
      init: {
        credentials: "include",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json"
        },
        method: "POST"
      },
      url: "https://identity.example.com/v1/passkeys/login/start"
    });
    expectJsonRequestBody(calls[0], {
      userId: "user_123"
    });
    expect(calls[1]).toMatchObject({
      init: {
        credentials: "include",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json"
        },
        method: "POST"
      },
      url: "https://identity.example.com/v1/passkeys/login/finish"
    });
    expectJsonRequestBody(calls[1], {
      credential: {
        authenticatorAttachment: "platform",
        clientExtensionResults: {},
        id: "credential_public_id",
        rawId: "credential_raw_id",
        response: {
          authenticatorData: "authenticator_data",
          clientDataJSON: "client_data_json",
          signature: "signature",
          userHandle: "user_handle"
        },
        type: "public-key"
      },
      deviceLabel: "Safari on macOS",
      loginId: "login_123"
    });
  });

  it("registers a recovery passkey through the browser ceremony", async () => {
    const registrationOptions: WebAuthnRegistrationOptions = {
      challenge: "recovery_registration_challenge",
      pubKeyCredParams: [{ alg: -7, type: "public-key" }],
      rp: {
        id: "identity.example.com",
        name: "SceauID"
      },
      user: {
        displayName: "Ibukunoluwa Kehinde",
        id: "user_123",
        name: "ibukunoluwa@example.com"
      }
    };
    const registrationCredential: WebAuthnRegistrationCredential = {
      clientExtensionResults: {},
      id: "credential_public_id",
      rawId: "credential_raw_id",
      response: {
        attestationObject: "attestation_object",
        clientDataJSON: "client_data_json"
      },
      type: "public-key"
    };
    const ceremonyCalls: unknown[] = [];
    const { calls, fetch } = createFetchSequenceStub([
      {
        body: {
          expiresAt: "2026-06-04T00:05:00.000Z",
          options: registrationOptions,
          registrationId: "registration_123"
        }
      },
      {
        body: {
          credential: {
            createdAt: "2026-06-04T00:01:00.000Z",
            credentialId: "credential_public_id",
            deviceName: "iPhone",
            id: "passkey_123"
          },
          userId: "user_123"
        }
      }
    ]);
    const client = new SceauIDBrowserClient({
      baseUrl: "https://identity.example.com",
      ceremonies: {
        startRegistration: async (options) => {
          ceremonyCalls.push(options);
          return registrationCredential;
        }
      },
      fetch
    });

    const result = await client.registerRecoveryPasskey({
      deviceName: "iPhone",
      recoverySessionToken: "recovery_session_token",
      userDisplayName: "Ibukunoluwa Kehinde",
      userName: "ibukunoluwa@example.com"
    });

    expect(result.credential.id).toBe("passkey_123");
    expect(ceremonyCalls).toEqual([
      {
        optionsJSON: registrationOptions,
        useAutoRegister: undefined
      }
    ]);
    expect(calls).toHaveLength(2);
    expect(calls[0]).toMatchObject({
      init: {
        credentials: "include",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json"
        },
        method: "POST"
      },
      url: "https://identity.example.com/v1/recovery/passkeys/registration/start"
    });
    expectJsonRequestBody(calls[0], {
      recoverySessionToken: "recovery_session_token",
      userDisplayName: "Ibukunoluwa Kehinde",
      userName: "ibukunoluwa@example.com"
    });
    expect(calls[1]).toMatchObject({
      init: {
        credentials: "include",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json"
        },
        method: "POST"
      },
      url: "https://identity.example.com/v1/passkeys/registration/finish"
    });
    expectJsonRequestBody(calls[1], {
      credential: {
        clientExtensionResults: {},
        id: "credential_public_id",
        rawId: "credential_raw_id",
        response: {
          attestationObject: "attestation_object",
          clientDataJSON: "client_data_json"
        },
        type: "public-key"
      },
      deviceName: "iPhone",
      registrationId: "registration_123"
    });
  });

  it("throws a structured SceauIDError for failed requests", async () => {
    const { fetch } = createFetchStub(
      {
        error: "login_start_failed",
        message: "User has no active passkeys"
      },
      { ok: false, status: 409 }
    );
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    await expect(client.startPasskeyLogin({ userId: "user_123" })).rejects.toMatchObject({
      code: "login_start_failed",
      message: "User has no active passkeys",
      status: 409
    });
    await expect(client.startPasskeyLogin({ userId: "user_123" })).rejects.toBeInstanceOf(
      SceauIDError
    );
  });
});
