import cookie from "@fastify/cookie";
import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import type { Session, SessionId, UserId } from "../domain/identity.js";
import { registerRecoveryRoutes } from "./recovery-routes.js";

const userId = "user-id" as UserId;
const session: Session = {
  id: "session-id" as SessionId,
  userId,
  tokenHash: "token-hash",
  deviceLabel: "Safari on macOS",
  userAgent: "test-agent",
  ipHash: null,
  expiresAt: new Date("2026-07-01T12:00:00.000Z"),
  revokedAt: null,
  createdAt: new Date("2026-06-01T12:00:00.000Z")
};

function createApp(options: { authenticatedSession?: Session | null } = {}) {
  const enrolledUsers: UserId[] = [];
  const statusUsers: UserId[] = [];
  const app = Fastify();

  void app.register(cookie);
  void registerRecoveryRoutes(app, {
    recoveryCodes: {
      async enroll(input) {
        enrolledUsers.push(input.userId);
        return {
          codes: ["AAAAA-BBBBB-CCCCC-DDDDD"],
          recoveryCodesConfigured: true,
          unusedRecoveryCodeCount: 1
        };
      },
      async status(statusUserId) {
        statusUsers.push(statusUserId);
        return {
          recoveryCodesConfigured: true,
          unusedRecoveryCodeCount: 3
        };
      }
    },
    sessionCookieName: "sceauid_session",
    sessionService: {
      async authenticate(token) {
        expect(token).toBe("session-token");
        return options.authenticatedSession ?? null;
      }
    }
  });

  return { app, enrolledUsers, statusUsers };
}

describe("recovery routes", () => {
  it("returns recovery status for the authenticated user", async () => {
    const { app, statusUsers } = createApp({ authenticatedSession: session });

    const response = await app.inject({
      method: "GET",
      url: "/v1/recovery/status",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(statusUsers).toEqual([userId]);
    expect(response.json()).toEqual({
      recoveryCodesConfigured: true,
      unusedRecoveryCodeCount: 3
    });
  });

  it("enrolls recovery codes for the authenticated user", async () => {
    const { app, enrolledUsers } = createApp({ authenticatedSession: session });

    const response = await app.inject({
      method: "POST",
      url: "/v1/recovery/codes",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(enrolledUsers).toEqual([userId]);
    expect(response.json()).toEqual({
      codes: ["AAAAA-BBBBB-CCCCC-DDDDD"],
      recoveryCodesConfigured: true,
      unusedRecoveryCodeCount: 1
    });
  });

  it("rejects recovery requests without a session cookie", async () => {
    const { app } = createApp({ authenticatedSession: session });

    const response = await app.inject({
      method: "GET",
      url: "/v1/recovery/status"
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({
      error: "unauthenticated",
      message: "Session cookie was not found"
    });
  });

  it("rejects recovery requests with an invalid session", async () => {
    const { app } = createApp({ authenticatedSession: null });

    const response = await app.inject({
      method: "POST",
      url: "/v1/recovery/codes",
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
});
