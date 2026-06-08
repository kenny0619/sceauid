import { describe, expect, it } from "vitest";
import { SceauIDClient, SceauIDError, type SceauIDFetchInit } from "./index.js";

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
        deviceLabel: "Safari on macOS",
        userAgent: "test-agent",
        expiresAt: "2026-07-04T12:00:00.000Z",
        createdAt: "2026-06-04T12:00:00.000Z"
      }
    });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const result = await client.currentSession();

    expect(result.user.id).toBe("user_123");
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
          deviceLabel: "Safari on macOS",
          userAgent: "test-agent",
          expiresAt: "2026-07-04T12:00:00.000Z",
          revokedAt: null,
          createdAt: "2026-06-04T12:00:00.000Z"
        }
      ]
    });
    const client = new SceauIDClient({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const result = await client.sessions();

    expect(result.sessions).toHaveLength(1);
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
        url: "https://identity.example.com/v1/security-events?limit=10&cursor=current-page-token&eventType=login_failed&eventType=session_revoked&outcome=failure&riskLevel=medium&riskLevel=high"
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
