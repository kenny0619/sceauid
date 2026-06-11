import { type ExecutionContext, UnauthorizedException } from "@nestjs/common";
import { SceauIDClient, type SceauIDFetchInit } from "@sceauid/sdk";
import { describe, expect, it } from "vitest";
import {
  SCEAUID_CLIENT,
  SCEAUID_MODULE_OPTIONS,
  SceauIDCurrentSessionGuard,
  SceauIDModule,
  SceauIDService,
  createSceauIDOptions,
  getSceauIDCurrentSession,
  resolveSceauIDCookieHeader
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
    deviceLabel: "Safari on macOS",
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

function createHttpContext(request: Record<string, unknown>): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => request
    })
  } as ExecutionContext;
}

describe("SceauID NestJS integration", () => {
  it("normalizes module options", () => {
    expect(createSceauIDOptions({ apiUrl: "https://identity.example.com" })).toEqual({
      baseUrl: "https://identity.example.com",
      fetch: undefined,
      sessionCookieName: "sceauid_session"
    });
    expect(
      createSceauIDOptions({
        baseUrl: "https://identity.example.com",
        sessionCookieName: "custom_session"
      })
    ).toMatchObject({
      baseUrl: "https://identity.example.com",
      sessionCookieName: "custom_session"
    });
    expect(() => createSceauIDOptions({})).toThrow("SceauID NestJS module requires baseUrl");
  });

  it("registers module providers and exports", () => {
    const moduleDefinition = SceauIDModule.register({
      baseUrl: "https://identity.example.com",
      global: true
    });

    expect(moduleDefinition.module).toBe(SceauIDModule);
    expect(moduleDefinition.global).toBe(true);
    expect(moduleDefinition.providers).toEqual(
      expect.arrayContaining([
        SceauIDCurrentSessionGuard,
        expect.objectContaining({ provide: SCEAUID_MODULE_OPTIONS }),
        expect.objectContaining({ provide: SCEAUID_CLIENT }),
        expect.objectContaining({ provide: SceauIDService })
      ])
    );
    expect(moduleDefinition.exports).toEqual(
      expect.arrayContaining([SceauIDService, SceauIDCurrentSessionGuard, SCEAUID_CLIENT])
    );
  });

  it("resolves cookie headers from Nest request shapes", () => {
    expect(
      resolveSceauIDCookieHeader({
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
          }
        },
        "custom_session"
      )
    ).toBe("custom_session=session_token");
  });

  it("fetches the current session from an incoming request cookie", async () => {
    const { calls, fetch } = createFetchStub(currentSessionResponse);
    const options = createSceauIDOptions({
      baseUrl: "https://identity.example.com",
      fetch
    });
    const service = new SceauIDService(
      options,
      new SceauIDClient({
        baseUrl: options.baseUrl,
        fetch
      })
    );

    const result = await service.currentSessionFromRequest({
      headers: {
        cookie: "sceauid_session=session_token"
      }
    });

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
    const options = createSceauIDOptions({
      baseUrl: "https://identity.example.com",
      fetch
    });
    const service = new SceauIDService(
      options,
      new SceauIDClient({
        baseUrl: options.baseUrl,
        fetch
      })
    );

    await expect(service.currentSessionFromRequest({})).resolves.toBeNull();
    await expect(
      service.currentSessionFromRequest({
        headers: {
          cookie: "sceauid_session=expired_token"
        }
      })
    ).resolves.toBeNull();
  });

  it("guards requests with an active SceauID session", async () => {
    const request = {
      headers: {
        cookie: "sceauid_session=session_token"
      }
    };
    const guard = new SceauIDCurrentSessionGuard({
      currentSessionFromRequest: async () => currentSessionResponse
    } as unknown as SceauIDService);

    await expect(guard.canActivate(createHttpContext(request))).resolves.toBe(true);
    expect(getSceauIDCurrentSession(request)).toEqual(currentSessionResponse);
  });

  it("rejects guarded requests without an active SceauID session", async () => {
    const guard = new SceauIDCurrentSessionGuard({
      currentSessionFromRequest: async () => null
    } as unknown as SceauIDService);

    await expect(guard.canActivate(createHttpContext({ headers: {} }))).rejects.toBeInstanceOf(
      UnauthorizedException
    );
  });
});
