import cookie from "@fastify/cookie";
import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import type { Session, SessionId, User, UserId } from "../domain/identity.js";
import type { RecordSecurityEventInput } from "../security-events/security-event-service.js";
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
  securityEvents?: RecordSecurityEventInput[];
  sessionsForUser?: Session[];
}) {
  const app = Fastify();
  void app.register(cookie);
  void registerSessionRoutes(app, {
    securityEvents: {
      async record(input) {
        options.securityEvents?.push(input);
        return undefined as never;
      }
    },
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
    const recoverySession: Session = {
      ...session,
      id: "recovery-session-id" as SessionId,
      deviceLabel: "Recovery session",
      userAgent: null,
      expiresAt: new Date("2026-06-01T12:16:00.000Z"),
      createdAt: new Date("2026-06-01T12:01:00.000Z")
    };
    const app = createApp({
      authenticatedSession: session,
      foundUser: user,
      sessionsForUser: [session, otherSession, recoverySession]
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
          kind: "standard",
          deviceLabel: "Safari on macOS",
          userAgent: "test-agent",
          expiresAt: "2026-07-01T12:00:00.000Z",
          revokedAt: null,
          createdAt: "2026-06-01T12:00:00.000Z"
        },
        {
          id: "other-session-id",
          current: false,
          kind: "standard",
          deviceLabel: "Chrome on Windows",
          userAgent: "other-agent",
          expiresAt: "2026-07-02T12:00:00.000Z",
          revokedAt: "2026-06-03T12:00:00.000Z",
          createdAt: "2026-06-02T12:00:00.000Z"
        },
        {
          id: "recovery-session-id",
          current: false,
          kind: "recovery",
          deviceLabel: "Recovery session",
          userAgent: null,
          expiresAt: "2026-06-01T12:16:00.000Z",
          revokedAt: null,
          createdAt: "2026-06-01T12:01:00.000Z"
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
        kind: "standard",
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
    const securityEvents: RecordSecurityEventInput[] = [];
    const app = createApp({
      authenticatedSession: session,
      foundUser: user,
      revokedSessionIds,
      securityEvents
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
    expect(securityEvents).toEqual([
      {
        userId: "user-id",
        actorUserId: "user-id",
        sessionId: "session-id",
        eventType: "session_revoked",
        outcome: "success",
        metadata: {
          actorSessionId: "session-id",
          reason: "current_session_logout",
          self: true,
          targetCreatedAt: "2026-06-01T12:00:00.000Z",
          targetDeviceLabel: "Safari on macOS",
          targetExpiresAt: "2026-07-01T12:00:00.000Z",
          targetUserAgent: "test-agent"
        }
      }
    ]);
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
    const securityEvents: RecordSecurityEventInput[] = [];
    const otherSession: Session = {
      ...session,
      id: "other-session-id" as SessionId,
      deviceLabel: "Chrome on Windows"
    };
    const app = createApp({
      authenticatedSession: session,
      foundUser: user,
      revokedSessionIds,
      securityEvents,
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
    expect(securityEvents).toEqual([
      {
        userId: "user-id",
        actorUserId: "user-id",
        sessionId: "other-session-id",
        eventType: "session_revoked",
        outcome: "success",
        metadata: {
          actorSessionId: "session-id",
          reason: "targeted_revoke",
          self: false,
          targetCreatedAt: "2026-06-01T12:00:00.000Z",
          targetDeviceLabel: "Chrome on Windows",
          targetExpiresAt: "2026-07-01T12:00:00.000Z",
          targetUserAgent: "test-agent"
        }
      }
    ]);
  });

  it("clears the session cookie when revoking the current session by id", async () => {
    const revokedSessionIds: SessionId[] = [];
    const securityEvents: RecordSecurityEventInput[] = [];
    const app = createApp({
      authenticatedSession: session,
      foundUser: user,
      revokedSessionIds,
      securityEvents,
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
    expect(securityEvents).toEqual([
      {
        userId: "user-id",
        actorUserId: "user-id",
        sessionId: "session-id",
        eventType: "session_revoked",
        outcome: "success",
        metadata: {
          actorSessionId: "session-id",
          reason: "targeted_revoke",
          self: true,
          targetCreatedAt: "2026-06-01T12:00:00.000Z",
          targetDeviceLabel: "Safari on macOS",
          targetExpiresAt: "2026-07-01T12:00:00.000Z",
          targetUserAgent: "test-agent"
        }
      }
    ]);
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
