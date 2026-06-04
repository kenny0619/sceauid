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
}) {
  const app = Fastify();
  void app.register(cookie);
  void registerSessionRoutes(app, {
    sessionCookieName: "sceauid_session",
    sessionService: {
      async authenticate(token) {
        expect(token).toBe("session-token");
        return options.authenticatedSession ?? null;
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
});
