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
