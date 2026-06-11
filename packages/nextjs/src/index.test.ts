import { SceauIDError, type SceauIDFetchInit } from "@sceauid/sdk";
import { describe, expect, it } from "vitest";
import {
  createSceauIDMiddleware,
  createSceauIDNext,
  createSceauIDOptions,
  currentSessionFromCookieHeader,
  currentSessionFromCookies,
  currentSessionFromRequest,
  unauthorizedResponse
} from "./index.js";

type FetchCall = {
  init?: SceauIDFetchInit;
  url: string;
};

const currentSessionResponse = {
  user: {
    id: "user_123",
    displayName: "Ibukunoluwa Kehinde",
    status: "active" as const
  },
  session: {
    id: "session_123",
    kind: "standard" as const,
    deviceLabel: "Chrome on macOS",
    userAgent: "test-agent",
    expiresAt: "2026-07-01T12:00:00.000Z",
    authenticatedAt: "2026-06-01T11:55:00.000Z",
    createdAt: "2026-06-01T12:00:00.000Z"
  }
};

function createFetchStub(body: unknown, options: { ok?: boolean; status?: number } = {}) {
  const calls: FetchCall[] = [];
  const fetch = async (url: string, init?: SceauIDFetchInit) => {
    calls.push({ init, url });

    return {
      ok: options.ok ?? true,
      status: options.status ?? 200,
      json: async () => body
    };
  };

  return { calls, fetch };
}

function createRequest(pathname = "/settings", cookie?: string): Request {
  return new Request(`https://app.example.com${pathname}`, {
    headers: cookie
      ? {
          cookie
        }
      : undefined
  });
}

describe("SceauID Next.js integration", () => {
  it("normalizes integration options", () => {
    expect(createSceauIDOptions({ apiUrl: "https://identity.example.com" })).toEqual({
      baseUrl: "https://identity.example.com",
      fetch: undefined,
      sessionCookieName: "sceauid_session",
      unauthorizedBody: {
        error: "unauthenticated",
        message: "SceauID session is required"
      }
    });
    expect(
      createSceauIDOptions({
        baseUrl: "https://identity.example.com",
        cookieName: "custom_session",
        unauthorizedBody: {
          error: "custom",
          message: "Custom response"
        }
      })
    ).toMatchObject({
      baseUrl: "https://identity.example.com",
      sessionCookieName: "custom_session",
      unauthorizedBody: {
        error: "custom",
        message: "Custom response"
      }
    });
    expect(() => createSceauIDOptions({})).toThrow("SceauID Next.js integration requires baseUrl");
  });

  it("creates server helpers and exposes the raw SDK client", () => {
    const integration = createSceauIDNext({
      baseUrl: "https://identity.example.com"
    });

    expect(integration.client).toBeDefined();
    expect(integration.currentSessionFromCookieHeader).toEqual(expect.any(Function));
    expect(integration.currentSessionFromCookies).toEqual(expect.any(Function));
    expect(integration.currentSessionFromRequest).toEqual(expect.any(Function));
    expect(integration.middleware).toEqual(expect.any(Function));
  });

  it("fetches the current session from a cookie header", async () => {
    const { calls, fetch } = createFetchStub(currentSessionResponse);

    const result = await currentSessionFromCookieHeader(
      {
        baseUrl: "https://identity.example.com",
        fetch
      },
      "sceauid_session=session_token"
    );

    expect(result).toEqual(currentSessionResponse);
    expect(calls).toEqual([
      {
        init: {
          body: undefined,
          credentials: "include",
          headers: {
            Accept: "application/json",
            Cookie: "sceauid_session=session_token"
          },
          method: "GET"
        },
        url: "https://identity.example.com/v1/sessions/current"
      }
    ]);
  });

  it("fetches the current session from Next cookies", async () => {
    const { fetch } = createFetchStub(currentSessionResponse);

    await expect(
      currentSessionFromCookies(
        {
          baseUrl: "https://identity.example.com",
          fetch,
          sessionCookieName: "identity_session"
        },
        {
          get: (name) => (name === "identity_session" ? { value: "session_token" } : undefined)
        }
      )
    ).resolves.toEqual(currentSessionResponse);
  });

  it("fetches the current session from a Next request", async () => {
    const { fetch } = createFetchStub(currentSessionResponse);

    await expect(
      currentSessionFromRequest(
        {
          baseUrl: "https://identity.example.com",
          fetch
        },
        createRequest("/settings", "sceauid_session=session_token")
      )
    ).resolves.toEqual(currentSessionResponse);
  });

  it("returns null for missing or invalid sessions", async () => {
    const { fetch } = createFetchStub(
      {
        error: "unauthenticated",
        message: "Session is invalid or expired"
      },
      { ok: false, status: 401 }
    );

    await expect(
      currentSessionFromRequest(
        {
          baseUrl: "https://identity.example.com",
          fetch
        },
        createRequest()
      )
    ).resolves.toBeNull();
    await expect(
      currentSessionFromRequest(
        {
          baseUrl: "https://identity.example.com",
          fetch
        },
        createRequest("/settings", "sceauid_session=expired_token")
      )
    ).resolves.toBeNull();
  });

  it("creates unauthorized JSON responses", async () => {
    const response = unauthorizedResponse({
      baseUrl: "https://identity.example.com",
      unauthorizedBody: {
        error: "login_required",
        message: "Sign in to continue"
      }
    });

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: "login_required",
      message: "Sign in to continue"
    });
  });

  it("allows public middleware paths without calling SceauID", async () => {
    const { calls, fetch } = createFetchStub(currentSessionResponse);
    const middleware = createSceauIDMiddleware({
      baseUrl: "https://identity.example.com",
      fetch,
      publicPaths: ["/login", /^\/public/]
    });

    const response = await middleware(createRequest("/login"));

    expect(response).toBeUndefined();
    expect(calls).toEqual([]);
  });

  it("continues authenticated middleware requests", async () => {
    const { fetch } = createFetchStub(currentSessionResponse);
    const middleware = createSceauIDMiddleware({
      baseUrl: "https://identity.example.com",
      fetch
    });

    const response = await middleware(createRequest("/settings", "sceauid_session=session_token"));

    expect(response).toBeUndefined();
  });

  it("returns a 401 response for unauthenticated middleware requests", async () => {
    const middleware = createSceauIDMiddleware({
      baseUrl: "https://identity.example.com",
      fetch: createFetchStub(null).fetch
    });

    const response = await middleware(createRequest("/settings"));

    if (!response) {
      throw new Error("Expected middleware to return an unauthorized response");
    }

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: "unauthenticated",
      message: "SceauID session is required"
    });
  });

  it("redirects unauthenticated middleware requests when configured", async () => {
    const middleware = createSceauIDMiddleware({
      baseUrl: "https://identity.example.com",
      fetch: createFetchStub(null).fetch,
      loginPath: "/login",
      redirectToLogin: true
    });

    const response = await middleware(createRequest("/settings?tab=security"));

    if (!response) {
      throw new Error("Expected middleware to return a redirect response");
    }

    expect(response.status).toBe(307);
    expect(response.headers.get("location")).toBe(
      "https://app.example.com/login?next=%2Fsettings%3Ftab%3Dsecurity"
    );
  });

  it("passes non-authentication errors through middleware", async () => {
    const error = new SceauIDError(500, {
      error: "server_error",
      message: "SceauID is unavailable"
    });
    const middleware = createSceauIDMiddleware({
      baseUrl: "https://identity.example.com",
      fetch: async () => {
        throw error;
      }
    });

    await expect(
      middleware(createRequest("/settings", "sceauid_session=session_token"))
    ).rejects.toBe(error);
  });
});
