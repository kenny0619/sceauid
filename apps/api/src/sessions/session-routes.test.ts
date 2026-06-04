import cookie from "@fastify/cookie";
import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import type { Session, SessionId, User, UserId } from "../domain/identity.js";
import { registerSessionRoutes } from "./session-routes.js";

const user: User = {
  id: "user-id" as UserId,
  displayName: "Test User",
  status: "active",
  createdAt: new Date("2026-06-01T12:00:00.000Z"),
  updatedAt: new Date("2026-06-01T12:00:00.000Z")
};

const session: Session = {
  id: "session-id" as SessionId,
  userId: user.id,
  tokenHash: "token-hash",
  deviceLabel: "Safari on macOS",
  userAgent: "test-agent",
  ipHash: null,
  expiresAt: new Date("2026-07-01T12:00:00.000Z"),
  revokedAt: null,
  createdAt: new Date("2026-06-01T12:00:00.000Z")
};

function createApp(options: {
  authenticatedSession?: Session | null;
  foundUser?: User | null;
  revokedSessionIds?: SessionId[];
  sessionsForUser?: Session[];
}) {
  const app = Fastify();
  void app.register(cookie);
  void registerSessionRoutes(app, {
    sessionCookie: {
      name: "sceauid_session",
      secure: true
    },
    sessionService: {
      async authenticate(token) {
        expect(token).toBe("session-token");
        return options.authenticatedSession ?? null;
      },
      async listForUser(userId) {
        expect(userId).toBe(user.id);
        return options.sessionsForUser ?? [];
      },
      async revoke(sessionId) {
        options.revokedSessionIds?.push(sessionId);
      }
    },
    store: {
      async findUserById(userId) {
        expect(userId).toBe(user.id);
        return options.foundUser ?? null;
      }
    }
  });

  return app;
}

describe("session routes", () => {
  it("lists sessions for the authenticated user", async () => {
    const otherSession: Session = {
      ...session,
      id: "other-session-id" as SessionId,
      deviceLabel: "Chrome on Windows",
      userAgent: "other-agent",
      expiresAt: new Date("2026-07-02T12:00:00.000Z"),
      revokedAt: new Date("2026-06-03T12:00:00.000Z"),
      createdAt: new Date("2026-06-02T12:00:00.000Z")
    };
    const app = createApp({
      authenticatedSession: session,
      foundUser: user,
      sessionsForUser: [session, otherSession]
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/sessions",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      sessions: [
        {
          id: "session-id",
          current: true,
          deviceLabel: "Safari on macOS",
          userAgent: "test-agent",
          expiresAt: "2026-07-01T12:00:00.000Z",
          revokedAt: null,
          createdAt: "2026-06-01T12:00:00.000Z"
        },
        {
          id: "other-session-id",
          current: false,
          deviceLabel: "Chrome on Windows",
          userAgent: "other-agent",
          expiresAt: "2026-07-02T12:00:00.000Z",
          revokedAt: "2026-06-03T12:00:00.000Z",
          createdAt: "2026-06-02T12:00:00.000Z"
        }
      ]
    });
  });

  it("rejects session list requests without a session cookie", async () => {
    const app = createApp({
      authenticatedSession: session,
      foundUser: user,
      sessionsForUser: [session]
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/sessions"
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({
      error: "unauthenticated",
      message: "Session cookie was not found"
    });
  });

  it("rejects session list requests with an invalid session", async () => {
    const app = createApp({
      authenticatedSession: null,
      foundUser: user,
      sessionsForUser: [session]
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/sessions",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({
      error: "unauthenticated",
      message: "Session is invalid or expired"
    });
  });

  it("returns the current user and session for a valid session cookie", async () => {
    const app = createApp({
      authenticatedSession: session,
      foundUser: user
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/sessions/current",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      user: {
        id: "user-id",
        displayName: "Test User",
        status: "active"
      },
      session: {
        id: "session-id",
        deviceLabel: "Safari on macOS",
        userAgent: "test-agent",
        expiresAt: "2026-07-01T12:00:00.000Z",
        createdAt: "2026-06-01T12:00:00.000Z"
      }
    });
  });

  it("rejects requests without a session cookie", async () => {
    const app = createApp({
      authenticatedSession: session,
      foundUser: user
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/sessions/current"
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({
      error: "unauthenticated",
      message: "Session cookie was not found"
    });
  });

  it("rejects invalid or expired sessions", async () => {
    const app = createApp({
      authenticatedSession: null,
      foundUser: user
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/sessions/current",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({
      error: "unauthenticated",
      message: "Session is invalid or expired"
    });
  });

  it("rejects sessions whose user cannot be found", async () => {
    const app = createApp({
      authenticatedSession: session,
      foundUser: null
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/sessions/current",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({
      error: "unauthenticated",
      message: "Session user was not found"
    });
  });

  it("revokes the current session and clears the session cookie", async () => {
    const revokedSessionIds: SessionId[] = [];
    const app = createApp({
      authenticatedSession: session,
      foundUser: user,
      revokedSessionIds
    });

    const response = await app.inject({
      method: "DELETE",
      url: "/v1/sessions/current",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ ok: true });
    expect(revokedSessionIds).toEqual(["session-id"]);
    expect(response.headers["set-cookie"]).toContain("sceauid_session=;");
    expect(response.headers["set-cookie"]).toContain("Path=/");
    expect(response.headers["set-cookie"]).toContain("Secure");
    expect(response.headers["set-cookie"]).toContain("SameSite=Lax");
  });

  it("clears the session cookie even when no active session exists", async () => {
    const revokedSessionIds: SessionId[] = [];
    const app = createApp({
      authenticatedSession: null,
      foundUser: user,
      revokedSessionIds
    });

    const response = await app.inject({
      method: "DELETE",
      url: "/v1/sessions/current",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ ok: true });
    expect(revokedSessionIds).toEqual([]);
    expect(response.headers["set-cookie"]).toContain("sceauid_session=;");
  });

  it("clears the session cookie even when the request has no cookie", async () => {
    const revokedSessionIds: SessionId[] = [];
    const app = createApp({
      authenticatedSession: session,
      foundUser: user,
      revokedSessionIds
    });

    const response = await app.inject({
      method: "DELETE",
      url: "/v1/sessions/current"
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ ok: true });
    expect(revokedSessionIds).toEqual([]);
    expect(response.headers["set-cookie"]).toContain("sceauid_session=;");
  });

  it("revokes another session owned by the authenticated user", async () => {
    const revokedSessionIds: SessionId[] = [];
    const otherSession: Session = {
      ...session,
      id: "other-session-id" as SessionId,
      deviceLabel: "Chrome on Windows"
    };
    const app = createApp({
      authenticatedSession: session,
      foundUser: user,
      revokedSessionIds,
      sessionsForUser: [session, otherSession]
    });

    const response = await app.inject({
      method: "DELETE",
      url: "/v1/sessions/other-session-id",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ ok: true });
    expect(revokedSessionIds).toEqual(["other-session-id"]);
    expect(response.headers["set-cookie"]).toBeUndefined();
  });

  it("clears the session cookie when revoking the current session by id", async () => {
    const revokedSessionIds: SessionId[] = [];
    const app = createApp({
      authenticatedSession: session,
      foundUser: user,
      revokedSessionIds,
      sessionsForUser: [session]
    });

    const response = await app.inject({
      method: "DELETE",
      url: "/v1/sessions/session-id",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ ok: true });
    expect(revokedSessionIds).toEqual(["session-id"]);
    expect(response.headers["set-cookie"]).toContain("sceauid_session=;");
  });

  it("rejects session revoke requests for sessions outside the authenticated user", async () => {
    const revokedSessionIds: SessionId[] = [];
    const app = createApp({
      authenticatedSession: session,
      foundUser: user,
      revokedSessionIds,
      sessionsForUser: [session]
    });

    const response = await app.inject({
      method: "DELETE",
      url: "/v1/sessions/foreign-session-id",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({
      error: "session_not_found",
      message: "Session was not found"
    });
    expect(revokedSessionIds).toEqual([]);
  });

  it("rejects session revoke requests without a session cookie", async () => {
    const revokedSessionIds: SessionId[] = [];
    const app = createApp({
      authenticatedSession: session,
      foundUser: user,
      revokedSessionIds,
      sessionsForUser: [session]
    });

    const response = await app.inject({
      method: "DELETE",
      url: "/v1/sessions/session-id"
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({
      error: "unauthenticated",
      message: "Session cookie was not found"
    });
    expect(revokedSessionIds).toEqual([]);
  });

  it("rejects session revoke requests with an invalid session", async () => {
    const revokedSessionIds: SessionId[] = [];
    const app = createApp({
      authenticatedSession: null,
      foundUser: user,
      revokedSessionIds,
      sessionsForUser: [session]
    });

    const response = await app.inject({
      method: "DELETE",
      url: "/v1/sessions/session-id",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({
      error: "unauthenticated",
      message: "Session is invalid or expired"
    });
    expect(revokedSessionIds).toEqual([]);
  });
});
