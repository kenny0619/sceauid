import cookie from "@fastify/cookie";
import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import type { RecoveryRequestId, Session, SessionId, UserId } from "../domain/identity.js";
import type { RiskStore } from "../domain/storage.js";
import type { SecurityEventService } from "../security-events/security-event-service.js";
import { registerRecoveryRoutes } from "./recovery-routes.js";

const userId = "user-id" as UserId;
const recoveryRequestId = "recovery-request-id" as RecoveryRequestId;
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

const recoverySession: Session = {
  ...session,
  id: "recovery-session-id" as SessionId,
  deviceLabel: "Recovery session"
};

function createApp(
  options: {
    authenticatedSession?: Session | null;
    recoverySession?: Session | null;
    rejectCompletion?: "expired" | "not_found" | "not_pending";
    rejectRegistrationStart?: "not_active" | "not_found";
    rejectRecoveryRequestLookup?: boolean;
    rejectRedemption?: "invalid" | "rate_limited" | boolean;
    startRateLimitAllowed?: boolean;
  } = {}
) {
  const enrollments: Array<{ actorSessionId?: SessionId | null; userId: UserId }> = [];
  const rateLimitChecks: Array<{ key: string; limit: number; windowSeconds: number }> = [];
  const registrationStarts: Array<{
    context?: {
      flow?: "recovery" | "standard";
      recoverySessionId?: string;
    };
    userDisplayName?: string | null;
    userId: UserId;
    userName: string;
  }> = [];
  const recordedEvents: Array<Parameters<SecurityEventService["record"]>[0]> = [];
  const redeemedCodes: Array<{ code: string; userId: UserId }> = [];
  const statusUsers: UserId[] = [];
  const app = Fastify();
  const riskStore: RiskStore = {
    async checkRateLimit(key, limit, windowSeconds) {
      rateLimitChecks.push({ key, limit, windowSeconds });

      return {
        allowed: options.startRateLimitAllowed ?? true,
        limit,
        remaining: options.startRateLimitAllowed === false ? 0 : limit - 1,
        resetAt: new Date("2026-06-01T12:15:00.000Z")
      };
    }
  };

  void app.register(cookie);
  void registerRecoveryRoutes(app, {
    passkeyRegistrationStartService: {
      async start(input) {
        registrationStarts.push(input);

        if (options.rejectRegistrationStart === "not_found") {
          throw new Error("User was not found");
        }

        if (options.rejectRegistrationStart === "not_active") {
          throw new Error("User cannot register passkeys unless active");
        }

        return {
          registrationId: "registration-id",
          expiresAt: new Date("2026-06-01T12:05:00.000Z"),
          options: {
            challenge: "challenge",
            pubKeyCredParams: [],
            rp: {
              id: "identity.example.com",
              name: "SceauID"
            },
            user: {
              displayName: "Ibukunoluwa Kehinde",
              id: "user-id",
              name: "ibukunoluwa@example.com"
            }
          }
        };
      }
    },
    recoveryCodes: {
      async completeRecoveryRequest(statusRecoveryRequestId) {
        if (options.rejectCompletion === "not_found") {
          throw new Error("Recovery request was not found");
        }

        if (options.rejectCompletion === "expired") {
          throw new Error("Recovery request is expired");
        }

        if (options.rejectCompletion === "not_pending") {
          throw new Error("Recovery request is not pending");
        }

        return {
          ok: true,
          recoverySession: {
            id: "recovery-session-id" as SessionId,
            token: "recovery-session-token",
            expiresAt: new Date("2026-06-01T12:16:00.000Z")
          },
          recoveryRequest: {
            id: statusRecoveryRequestId,
            completedAt: new Date("2026-06-01T12:01:00.000Z"),
            status: "completed"
          }
        };
      },
      async enroll(input) {
        enrollments.push(input);
        return {
          codes: ["AAAAA-BBBBB-CCCCC-DDDDD"],
          recoveryCodesConfigured: true,
          unusedRecoveryCodeCount: 1
        };
      },
      async redeem(input) {
        redeemedCodes.push(input);

        if (options.rejectRedemption === true || options.rejectRedemption === "invalid") {
          throw new Error("Recovery code was invalid or already used");
        }

        if (options.rejectRedemption === "rate_limited") {
          throw new Error("Recovery code redemption rate limit exceeded");
        }

        return {
          ok: true,
          recoveryRequest: {
            id: recoveryRequestId,
            expiresAt: new Date("2026-06-01T12:15:00.000Z"),
            riskLevel: "medium"
          }
        };
      },
      async recoveryRequestStatus(statusRecoveryRequestId) {
        if (options.rejectRecoveryRequestLookup) {
          throw new Error("Recovery request was not found");
        }

        return {
          recoveryRequest: {
            id: statusRecoveryRequestId,
            active: true,
            expiresAt: new Date("2026-06-01T12:15:00.000Z"),
            riskLevel: "medium",
            status: "pending"
          }
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
    riskStore,
    securityEvents: {
      async record(input) {
        recordedEvents.push(input);
        return undefined as never;
      }
    },
    sessionService: {
      async authenticate(token) {
        if (token === "recovery-session-token") {
          return options.recoverySession === undefined ? recoverySession : options.recoverySession;
        }

        return options.authenticatedSession ?? null;
      }
    }
  });

  return {
    app,
    enrollments,
    rateLimitChecks,
    recordedEvents,
    redeemedCodes,
    registrationStarts,
    statusUsers
  };
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
    const { app, enrollments } = createApp({ authenticatedSession: session });

    const response = await app.inject({
      method: "POST",
      url: "/v1/recovery/codes",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(enrollments).toEqual([
      {
        actorSessionId: session.id,
        userId
      }
    ]);
    expect(response.json()).toEqual({
      codes: ["AAAAA-BBBBB-CCCCC-DDDDD"],
      recoveryCodesConfigured: true,
      unusedRecoveryCodeCount: 1
    });
  });

  it("redeems a recovery code without requiring a session", async () => {
    const { app, redeemedCodes } = createApp();

    const response = await app.inject({
      method: "POST",
      url: "/v1/recovery/codes/redeem",
      payload: {
        code: "AAAAA-BBBBB-CCCCC-DDDDD",
        userId
      }
    });

    expect(response.statusCode).toBe(200);
    expect(redeemedCodes).toEqual([
      {
        code: "AAAAA-BBBBB-CCCCC-DDDDD",
        userId
      }
    ]);
    expect(response.json()).toEqual({
      ok: true,
      recoveryRequest: {
        id: recoveryRequestId,
        expiresAt: "2026-06-01T12:15:00.000Z",
        riskLevel: "medium"
      }
    });
  });

  it("rejects invalid recovery code redemption payloads", async () => {
    const { app } = createApp();

    const response = await app.inject({
      method: "POST",
      url: "/v1/recovery/codes/redeem",
      payload: {
        code: ""
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({
      error: "invalid_request",
      message: "Recovery code redemption request is invalid"
    });
  });

  it("returns a generic error for invalid or used recovery codes", async () => {
    const { app } = createApp({ rejectRedemption: "invalid" });

    const response = await app.inject({
      method: "POST",
      url: "/v1/recovery/codes/redeem",
      payload: {
        code: "AAAAA-BBBBB-CCCCC-DDDDD",
        userId
      }
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({
      error: "invalid_recovery_code",
      message: "Recovery code is invalid or already used"
    });
  });

  it("returns rate limited when recovery code redemption attempts are exhausted", async () => {
    const { app } = createApp({ rejectRedemption: "rate_limited" });

    const response = await app.inject({
      method: "POST",
      url: "/v1/recovery/codes/redeem",
      payload: {
        code: "AAAAA-BBBBB-CCCCC-DDDDD",
        userId
      }
    });

    expect(response.statusCode).toBe(429);
    expect(response.json()).toEqual({
      error: "rate_limited",
      message: "Too many recovery code redemption attempts"
    });
  });

  it("returns recovery request status", async () => {
    const { app } = createApp();

    const response = await app.inject({
      method: "GET",
      url: `/v1/recovery/requests/${recoveryRequestId}`
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      recoveryRequest: {
        id: recoveryRequestId,
        active: true,
        expiresAt: "2026-06-01T12:15:00.000Z",
        riskLevel: "medium",
        status: "pending"
      }
    });
  });

  it("returns not found for unknown recovery requests", async () => {
    const { app } = createApp({ rejectRecoveryRequestLookup: true });

    const response = await app.inject({
      method: "GET",
      url: `/v1/recovery/requests/${recoveryRequestId}`
    });

    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({
      error: "recovery_request_not_found",
      message: "Recovery request was not found"
    });
  });

  it("completes recovery requests", async () => {
    const { app } = createApp();

    const response = await app.inject({
      method: "POST",
      url: `/v1/recovery/requests/${recoveryRequestId}/complete`
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      ok: true,
      recoverySession: {
        id: "recovery-session-id",
        token: "recovery-session-token",
        expiresAt: "2026-06-01T12:16:00.000Z"
      },
      recoveryRequest: {
        id: recoveryRequestId,
        completedAt: "2026-06-01T12:01:00.000Z",
        status: "completed"
      }
    });
  });

  it("returns not found when completing unknown recovery requests", async () => {
    const { app } = createApp({ rejectCompletion: "not_found" });

    const response = await app.inject({
      method: "POST",
      url: `/v1/recovery/requests/${recoveryRequestId}/complete`
    });

    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({
      error: "recovery_request_not_found",
      message: "Recovery request was not found"
    });
  });

  it("rejects expired recovery request completion", async () => {
    const { app } = createApp({ rejectCompletion: "expired" });

    const response = await app.inject({
      method: "POST",
      url: `/v1/recovery/requests/${recoveryRequestId}/complete`
    });

    expect(response.statusCode).toBe(409);
    expect(response.json()).toEqual({
      error: "recovery_request_expired",
      message: "Recovery request is expired"
    });
  });

  it("rejects non-pending recovery request completion", async () => {
    const { app } = createApp({ rejectCompletion: "not_pending" });

    const response = await app.inject({
      method: "POST",
      url: `/v1/recovery/requests/${recoveryRequestId}/complete`
    });

    expect(response.statusCode).toBe(409);
    expect(response.json()).toEqual({
      error: "recovery_request_not_pending",
      message: "Recovery request is not pending"
    });
  });

  it("starts passkey registration with a recovery session", async () => {
    const { app, rateLimitChecks, recordedEvents, registrationStarts } = createApp();

    const response = await app.inject({
      method: "POST",
      url: "/v1/recovery/passkeys/registration/start",
      payload: {
        recoverySessionToken: "recovery-session-token",
        userName: "ibukunoluwa@example.com",
        userDisplayName: "Ibukunoluwa Kehinde"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(rateLimitChecks).toEqual([
      {
        key: "recovery-passkey-registration-start:session:recovery-session-id",
        limit: 3,
        windowSeconds: 900
      }
    ]);
    expect(recordedEvents).toEqual([]);
    expect(registrationStarts).toEqual([
      {
        context: {
          flow: "recovery",
          recoverySessionId: recoverySession.id
        },
        userId,
        userName: "ibukunoluwa@example.com",
        userDisplayName: "Ibukunoluwa Kehinde"
      }
    ]);
    expect(response.json()).toEqual({
      registrationId: "registration-id",
      expiresAt: "2026-06-01T12:05:00.000Z",
      options: {
        challenge: "challenge",
        pubKeyCredParams: [],
        rp: {
          id: "identity.example.com",
          name: "SceauID"
        },
        user: {
          displayName: "Ibukunoluwa Kehinde",
          id: "user-id",
          name: "ibukunoluwa@example.com"
        }
      }
    });
  });

  it("rate limits recovery passkey registration starts by recovery session", async () => {
    const { app, rateLimitChecks, recordedEvents, registrationStarts } = createApp({
      startRateLimitAllowed: false
    });

    const response = await app.inject({
      method: "POST",
      url: "/v1/recovery/passkeys/registration/start",
      payload: {
        recoverySessionToken: "recovery-session-token",
        userName: "ibukunoluwa@example.com"
      }
    });

    expect(response.statusCode).toBe(429);
    expect(response.json()).toEqual({
      error: "rate_limited",
      message: "Too many recovery passkey registration attempts"
    });
    expect(rateLimitChecks).toEqual([
      {
        key: "recovery-passkey-registration-start:session:recovery-session-id",
        limit: 3,
        windowSeconds: 900
      }
    ]);
    expect(registrationStarts).toEqual([]);
    expect(recordedEvents).toEqual([
      {
        actorUserId: userId,
        eventType: "rate_limit_triggered",
        metadata: {
          limit: 3,
          remaining: 0,
          resetAt: "2026-06-01T12:15:00.000Z",
          scope: "recovery_passkey_registration_start",
          windowSeconds: 900
        },
        outcome: "failure",
        riskLevel: "medium",
        sessionId: recoverySession.id,
        userId
      }
    ]);
  });

  it("rejects invalid recovery sessions for passkey registration", async () => {
    const { app } = createApp({ recoverySession: null });

    const response = await app.inject({
      method: "POST",
      url: "/v1/recovery/passkeys/registration/start",
      payload: {
        recoverySessionToken: "recovery-session-token",
        userName: "ibukunoluwa@example.com"
      }
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({
      error: "invalid_recovery_session",
      message: "Recovery session is invalid or expired"
    });
  });

  it("rejects non-recovery sessions for recovery passkey registration", async () => {
    const { app } = createApp({ recoverySession: session });

    const response = await app.inject({
      method: "POST",
      url: "/v1/recovery/passkeys/registration/start",
      payload: {
        recoverySessionToken: "recovery-session-token",
        userName: "ibukunoluwa@example.com"
      }
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({
      error: "invalid_recovery_session",
      message: "Recovery session is invalid or expired"
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
