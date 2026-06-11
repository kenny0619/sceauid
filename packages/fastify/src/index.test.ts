import { SceauIDError, type SceauIDFetchInit } from "@sceauid/sdk";
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import { describe, expect, it } from "vitest";
import {
  createSceauIDCurrentSessionPreHandler,
  createSceauIDFastify,
  createSceauIDOptions,
  currentSessionFromRequest,
  getSceauIDCurrentSession,
  requireSceauIDCurrentSession,
  resolveSceauIDCookieHeader,
  sceauidFastify
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
    deviceLabel: "Arc on macOS",
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

describe("SceauID Fastify integration", () => {
  it("normalizes plugin options", () => {
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
    expect(() => createSceauIDOptions({})).toThrow("SceauID Fastify plugin requires baseUrl");
  });

  it("creates preHandlers and exposes the raw SDK client", () => {
    const integration = createSceauIDFastify({
      baseUrl: "https://identity.example.com"
    });

    expect(integration.client).toBeDefined();
    expect(integration.currentSession).toEqual(expect.any(Function));
    expect(integration.currentSessionFromRequest).toEqual(expect.any(Function));
    expect(integration.requireCurrentSession).toEqual(expect.any(Function));
  });

  it("decorates a Fastify app with SceauID helpers", async () => {
    const app = Fastify();

    await app.register(sceauidFastify({ baseUrl: "https://identity.example.com" }));

    expect(app.sceauid.client).toBeDefined();
    expect(app.sceauid.currentSession).toEqual(expect.any(Function));
    expect(app.sceauid.requireCurrentSession).toEqual(expect.any(Function));

    await app.close();
  });

  it("resolves cookie headers from Fastify request shapes", () => {
    expect(
      resolveSceauIDCookieHeader({
        cookies: {},
        headers: {
          cookie: "sceauid_session=session_token; theme=light"
        }
      })
    ).toBe("sceauid_session=session_token; theme=light");
    expect(
      resolveSceauIDCookieHeader(
        {
          cookies: {
            custom_session: "session_token"
          },
          headers: {}
        },
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
      } as unknown as FastifyRequest
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
      } as unknown as FastifyRequest)
    ).resolves.toBeNull();
    await expect(
      currentSessionFromRequest({ baseUrl: "https://identity.example.com", fetch }, {
        headers: {
          cookie: "sceauid_session=expired_token"
        }
      } as unknown as FastifyRequest)
    ).resolves.toBeNull();
  });

  it("loads optional current sessions before route handlers", async () => {
    const app = Fastify();

    await app.register(
      sceauidFastify({
        baseUrl: "https://identity.example.com",
        fetch: createFetchStub(currentSessionResponse).fetch
      })
    );
    app.get("/profile", { preHandler: app.sceauid.currentSession }, async (request) => ({
      currentSession: getSceauIDCurrentSession(request)
    }));

    const response = await app.inject({
      method: "GET",
      url: "/profile",
      headers: {
        cookie: "sceauid_session=session_token"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      currentSession: currentSessionResponse
    });

    await app.close();
  });

  it("requires current sessions before route handlers", async () => {
    const app = Fastify();

    await app.register(
      sceauidFastify({
        baseUrl: "https://identity.example.com",
        fetch: createFetchStub(currentSessionResponse).fetch
      })
    );
    app.get("/settings", { preHandler: app.sceauid.requireCurrentSession }, async (request) => ({
      currentSession: getSceauIDCurrentSession(request)
    }));

    const response = await app.inject({
      method: "GET",
      url: "/settings",
      headers: {
        cookie: "sceauid_session=session_token"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      currentSession: currentSessionResponse
    });

    await app.close();
  });

  it("returns a 401 response when required sessions are missing", async () => {
    const app = Fastify();

    await app.register(
      sceauidFastify({
        baseUrl: "https://identity.example.com",
        fetch: createFetchStub(null).fetch
      })
    );
    app.get("/settings", { preHandler: app.sceauid.requireCurrentSession }, async () => ({
      ok: true
    }));

    const response = await app.inject({
      method: "GET",
      url: "/settings"
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({
      error: "unauthenticated",
      message: "SceauID session is required"
    });

    await app.close();
  });

  it("lets Fastify handle non-authentication errors", async () => {
    const error = new SceauIDError(500, {
      error: "server_error",
      message: "SceauID is unavailable"
    });
    const app = Fastify();

    await app.register(
      sceauidFastify({
        baseUrl: "https://identity.example.com",
        fetch: async () => {
          throw error;
        }
      })
    );
    app.get("/profile", { preHandler: app.sceauid.currentSession }, async () => ({
      ok: true
    }));

    const response = await app.inject({
      method: "GET",
      url: "/profile",
      headers: {
        cookie: "sceauid_session=session_token"
      }
    });

    expect(response.statusCode).toBe(500);

    await app.close();
  });

  it("exports standalone preHandlers", async () => {
    const request = {
      headers: {
        cookie: "sceauid_session=session_token"
      }
    } as FastifyRequest;

    await createSceauIDCurrentSessionPreHandler({
      baseUrl: "https://identity.example.com",
      fetch: createFetchStub(currentSessionResponse).fetch
    }).call({} as FastifyInstance, request, {} as FastifyReply);

    expect(getSceauIDCurrentSession(request)).toEqual(currentSessionResponse);
  });
});
