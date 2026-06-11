import { SceauIDError, type SceauIDFetchInit } from "@sceauid/sdk";
import type { NextFunction, Request, Response } from "express";
import { describe, expect, it } from "vitest";
import {
  createSceauIDCurrentSessionMiddleware,
  createSceauIDExpress,
  createSceauIDOptions,
  currentSessionFromRequest,
  getSceauIDCurrentSession,
  requireSceauIDCurrentSession,
  resolveSceauIDCookieHeader
} from "./index.js";

type FetchCall = {
  init?: SceauIDFetchInit;
  url: string;
};

type ResponseStub = Pick<Response, "json" | "status"> & {
  body?: unknown;
  statusCode?: number;
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

function createResponseStub(): ResponseStub {
  const response = {
    status(code: number) {
      response.statusCode = code;
      return response as Response;
    },
    json(body: unknown) {
      response.body = body;
      return response as Response;
    }
  } as ResponseStub;

  return response;
}

function createNextRecorder() {
  const calls: unknown[] = [];
  const next: NextFunction = (error?: unknown) => {
    calls.push(error);
  };

  return { calls, next };
}

describe("SceauID Express integration", () => {
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
        sessionCookieName: "custom_session",
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
    expect(() => createSceauIDOptions({})).toThrow("SceauID Express integration requires baseUrl");
  });

  it("creates middleware and exposes the raw SDK client", () => {
    const integration = createSceauIDExpress({
      baseUrl: "https://identity.example.com"
    });

    expect(integration.client).toBeDefined();
    expect(integration.currentSession).toEqual(expect.any(Function));
    expect(integration.currentSessionFromRequest).toEqual(expect.any(Function));
    expect(integration.requireCurrentSession).toEqual(expect.any(Function));
  });

  it("resolves cookie headers from Express request shapes", () => {
    expect(
      resolveSceauIDCookieHeader({
        cookies: {},
        headers: {
          cookie: "sceauid_session=session_token; theme=light"
        }
      } as Request)
    ).toBe("sceauid_session=session_token; theme=light");
    expect(
      resolveSceauIDCookieHeader(
        {
          cookies: {
            custom_session: "session_token"
          },
          headers: {}
        } as Request,
        "custom_session"
      )
    ).toBe("custom_session=session_token");
  });

  it("fetches the current session from an incoming request cookie", async () => {
    const { calls, fetch } = createFetchStub(currentSessionResponse);

    const result = await currentSessionFromRequest(
      {
        baseUrl: "https://identity.example.com",
        fetch
      },
      {
        headers: {
          cookie: "sceauid_session=session_token"
        }
      } as Request
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

  it("returns null for missing or invalid request sessions", async () => {
    const { fetch } = createFetchStub(
      {
        error: "unauthenticated",
        message: "Session is invalid or expired"
      },
      { ok: false, status: 401 }
    );

    await expect(
      currentSessionFromRequest({ baseUrl: "https://identity.example.com", fetch }, {
        headers: {}
      } as Request)
    ).resolves.toBeNull();
    await expect(
      currentSessionFromRequest({ baseUrl: "https://identity.example.com", fetch }, {
        headers: {
          cookie: "sceauid_session=expired_token"
        }
      } as Request)
    ).resolves.toBeNull();
  });

  it("loads optional current session and continues", async () => {
    const { next, calls } = createNextRecorder();
    const middleware = createSceauIDCurrentSessionMiddleware({
      baseUrl: "https://identity.example.com",
      fetch: createFetchStub(currentSessionResponse).fetch
    });
    const request = {
      headers: {
        cookie: "sceauid_session=session_token"
      }
    } as Request;

    await middleware(request, createResponseStub() as Response, next);

    expect(calls).toEqual([undefined]);
    expect(getSceauIDCurrentSession(request)).toEqual(currentSessionResponse);
  });

  it("requires current session before continuing", async () => {
    const { next, calls } = createNextRecorder();
    const middleware = requireSceauIDCurrentSession({
      baseUrl: "https://identity.example.com",
      fetch: createFetchStub(currentSessionResponse).fetch
    });
    const request = {
      headers: {
        cookie: "sceauid_session=session_token"
      }
    } as Request;

    await middleware(request, createResponseStub() as Response, next);

    expect(calls).toEqual([undefined]);
    expect(getSceauIDCurrentSession(request)).toEqual(currentSessionResponse);
  });

  it("returns a 401 response when required sessions are missing", async () => {
    const { next, calls } = createNextRecorder();
    const response = createResponseStub();
    const middleware = requireSceauIDCurrentSession({
      baseUrl: "https://identity.example.com",
      fetch: createFetchStub(null).fetch
    });

    await middleware({ headers: {} } as Request, response as Response, next);

    expect(calls).toEqual([]);
    expect(response.statusCode).toBe(401);
    expect(response.body).toEqual({
      error: "unauthenticated",
      message: "SceauID session is required"
    });
  });

  it("passes non-authentication errors to next", async () => {
    const { next, calls } = createNextRecorder();
    const error = new SceauIDError(500, {
      error: "server_error",
      message: "SceauID is unavailable"
    });
    const middleware = createSceauIDCurrentSessionMiddleware({
      baseUrl: "https://identity.example.com",
      fetch: async () => {
        throw error;
      }
    });

    await middleware(
      {
        headers: {
          cookie: "sceauid_session=session_token"
        }
      } as Request,
      createResponseStub() as Response,
      next
    );

    expect(calls).toEqual([error]);
  });
});
