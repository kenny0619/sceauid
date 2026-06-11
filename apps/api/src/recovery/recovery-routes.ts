import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { RecoveryRequestId, UserId } from "../domain/identity.js";
import type { RiskStore } from "../domain/storage.js";
import type { PasskeyRegistrationStartService } from "../passkeys/passkey-registration-start-service.js";
import type { SecurityEventService } from "../security-events/security-event-service.js";
import { isFreshAuthentication, rejectFreshAuthRequired } from "../sessions/fresh-auth.js";
import { isRecoverySession, sessionKind } from "../sessions/session-kind.js";
import type { SessionService } from "../sessions/session-service.js";
import type { RecoveryCodeService } from "./recovery-code-service.js";

export type RecoveryRoutesDependencies = {
  passkeyRegistrationStartService: PasskeyRegistrationStartService;
  recoveryCodes: RecoveryCodeService;
  riskStore?: RiskStore;
  securityEvents?: Pick<SecurityEventService, "record">;
  sessionCookieName: string;
  sessionService: Pick<SessionService, "authenticate">;
  freshAuthWindowSeconds?: number;
  now?: () => Date;
};

const redeemRecoveryCodeBodySchema = z.object({
  code: z.string().min(1),
  userId: z.string().min(1)
});

const recoveryRequestParamsSchema = z.object({
  recoveryRequestId: z.string().min(1)
});

const recoveryPasskeyRegistrationStartBodySchema = z.object({
  recoverySessionToken: z.string().min(1),
  userName: z.string().min(1),
  userDisplayName: z.string().min(1).nullable().optional()
});

const recoveryPasskeyRegistrationStartRateLimit = {
  limit: 3,
  windowSeconds: 60 * 15
};

async function authenticateRequest(
  request: { cookies: Record<string, string | undefined> },
  dependencies: Pick<
    RecoveryRoutesDependencies,
    "freshAuthWindowSeconds" | "sessionCookieName" | "sessionService"
  >,
  reply: {
    status(statusCode: number): {
      send(payload: { error: string; message: string }): unknown;
    };
  },
  options: {
    now: Date;
    requireFreshAuth?: boolean;
  }
) {
  const token = request.cookies[dependencies.sessionCookieName];

  if (!token) {
    reply.status(401).send({
      error: "unauthenticated",
      message: "Session cookie was not found"
    });
    return null;
  }

  const session = await dependencies.sessionService.authenticate(token);

  if (!session) {
    reply.status(401).send({
      error: "unauthenticated",
      message: "Session is invalid or expired"
    });
    return null;
  }

  if (isRecoverySession(session)) {
    reply.status(403).send({
      error: "standard_session_required",
      message: "Recovery sessions cannot access this endpoint"
    });
    return null;
  }

  if (
    options.requireFreshAuth &&
    !isFreshAuthentication(session, options.now, {
      windowSeconds: dependencies.freshAuthWindowSeconds
    })
  ) {
    rejectFreshAuthRequired(reply);
    return null;
  }

  return session;
}

export async function registerRecoveryRoutes(
  app: FastifyInstance,
  dependencies: RecoveryRoutesDependencies
): Promise<void> {
  const now = dependencies.now ?? (() => new Date());

  app.get("/v1/recovery/status", async (request, reply) => {
    const session = await authenticateRequest(request, dependencies, reply, {
      now: now()
    });

    if (!session) {
      return;
    }

    return reply.send(await dependencies.recoveryCodes.status(session.userId));
  });

  app.post("/v1/recovery/codes", async (request, reply) => {
    const session = await authenticateRequest(request, dependencies, reply, {
      now: now(),
      requireFreshAuth: true
    });

    if (!session) {
      return;
    }

    return reply.send(
      await dependencies.recoveryCodes.enroll({
        actorSessionId: session.id,
        userId: session.userId
      })
    );
  });

  app.post("/v1/recovery/codes/redeem", async (request, reply) => {
    const body = redeemRecoveryCodeBodySchema.safeParse(request.body);

    if (!body.success) {
      return reply.status(400).send({
        error: "invalid_request",
        message: "Recovery code redemption request is invalid"
      });
    }

    try {
      return reply.send(
        await dependencies.recoveryCodes.redeem({
          code: body.data.code,
          userId: body.data.userId as UserId
        })
      );
    } catch (error) {
      if (error instanceof Error && error.message === "Recovery code was invalid or already used") {
        return reply.status(401).send({
          error: "invalid_recovery_code",
          message: "Recovery code is invalid or already used"
        });
      }

      if (
        error instanceof Error &&
        error.message === "Recovery code redemption rate limit exceeded"
      ) {
        return reply.status(429).send({
          error: "rate_limited",
          message: "Too many recovery code redemption attempts"
        });
      }

      throw error;
    }
  });

  app.get("/v1/recovery/requests/:recoveryRequestId", async (request, reply) => {
    const params = recoveryRequestParamsSchema.safeParse(request.params);

    if (!params.success) {
      return reply.status(400).send({
        error: "invalid_request",
        message: "Recovery request lookup is invalid"
      });
    }

    try {
      return reply.send(
        await dependencies.recoveryCodes.recoveryRequestStatus(
          params.data.recoveryRequestId as RecoveryRequestId
        )
      );
    } catch (error) {
      if (error instanceof Error && error.message === "Recovery request was not found") {
        return reply.status(404).send({
          error: "recovery_request_not_found",
          message: "Recovery request was not found"
        });
      }

      throw error;
    }
  });

  app.post("/v1/recovery/requests/:recoveryRequestId/complete", async (request, reply) => {
    const params = recoveryRequestParamsSchema.safeParse(request.params);

    if (!params.success) {
      return reply.status(400).send({
        error: "invalid_request",
        message: "Recovery request completion is invalid"
      });
    }

    try {
      return reply.send(
        await dependencies.recoveryCodes.completeRecoveryRequest(
          params.data.recoveryRequestId as RecoveryRequestId
        )
      );
    } catch (error) {
      if (error instanceof Error && error.message === "Recovery request was not found") {
        return reply.status(404).send({
          error: "recovery_request_not_found",
          message: "Recovery request was not found"
        });
      }

      if (error instanceof Error && error.message === "Recovery request is expired") {
        return reply.status(409).send({
          error: "recovery_request_expired",
          message: "Recovery request is expired"
        });
      }

      if (error instanceof Error && error.message === "Recovery request is not pending") {
        return reply.status(409).send({
          error: "recovery_request_not_pending",
          message: "Recovery request is not pending"
        });
      }

      throw error;
    }
  });

  app.delete("/v1/recovery/requests/:recoveryRequestId", async (request, reply) => {
    const params = recoveryRequestParamsSchema.safeParse(request.params);

    if (!params.success) {
      return reply.status(400).send({
        error: "invalid_request",
        message: "Recovery request cancellation is invalid"
      });
    }

    try {
      return reply.send(
        await dependencies.recoveryCodes.cancelRecoveryRequest(
          params.data.recoveryRequestId as RecoveryRequestId
        )
      );
    } catch (error) {
      if (error instanceof Error && error.message === "Recovery request was not found") {
        return reply.status(404).send({
          error: "recovery_request_not_found",
          message: "Recovery request was not found"
        });
      }

      if (error instanceof Error && error.message === "Recovery request is expired") {
        return reply.status(409).send({
          error: "recovery_request_expired",
          message: "Recovery request is expired"
        });
      }

      if (error instanceof Error && error.message === "Recovery request is not pending") {
        return reply.status(409).send({
          error: "recovery_request_not_pending",
          message: "Recovery request is not pending"
        });
      }

      throw error;
    }
  });

  app.post("/v1/recovery/passkeys/registration/start", async (request, reply) => {
    const body = recoveryPasskeyRegistrationStartBodySchema.safeParse(request.body);

    if (!body.success) {
      return reply.status(400).send({
        error: "invalid_request",
        message: "Recovery passkey registration start request is invalid"
      });
    }

    const recoverySession = await dependencies.sessionService.authenticate(
      body.data.recoverySessionToken
    );

    if (!recoverySession || !isRecoverySession(recoverySession)) {
      await dependencies.securityEvents
        ?.record({
          userId: recoverySession?.userId ?? null,
          actorUserId: recoverySession?.userId ?? null,
          sessionId: recoverySession?.id ?? null,
          eventType: "suspicious_activity_flagged",
          outcome: "failure",
          riskLevel: "medium",
          metadata: {
            reason: recoverySession ? "non_recovery_session" : "invalid_or_expired_session",
            scope: "recovery_passkey_registration_start",
            ...(recoverySession ? { sessionKind: sessionKind(recoverySession) } : {})
          }
        })
        .catch(() => undefined);

      return reply.status(401).send({
        error: "invalid_recovery_session",
        message: "Recovery session is invalid or expired"
      });
    }

    try {
      const rateLimit = await dependencies.riskStore?.checkRateLimit(
        `recovery-passkey-registration-start:session:${recoverySession.id}`,
        recoveryPasskeyRegistrationStartRateLimit.limit,
        recoveryPasskeyRegistrationStartRateLimit.windowSeconds
      );

      if (rateLimit && !rateLimit.allowed) {
        await dependencies.securityEvents
          ?.record({
            userId: recoverySession.userId,
            actorUserId: recoverySession.userId,
            sessionId: recoverySession.id,
            eventType: "rate_limit_triggered",
            outcome: "failure",
            riskLevel: "medium",
            metadata: {
              limit: rateLimit.limit,
              remaining: rateLimit.remaining,
              recoverySessionId: recoverySession.id,
              resetAt: rateLimit.resetAt.toISOString(),
              scope: "recovery_passkey_registration_start",
              windowSeconds: recoveryPasskeyRegistrationStartRateLimit.windowSeconds
            }
          })
          .catch(() => undefined);

        return reply.status(429).send({
          error: "rate_limited",
          message: "Too many recovery passkey registration attempts"
        });
      }

      return reply.send(
        await dependencies.passkeyRegistrationStartService.start({
          context: {
            flow: "recovery",
            recoverySessionId: recoverySession.id
          },
          userId: recoverySession.userId,
          userName: body.data.userName,
          userDisplayName: body.data.userDisplayName
        })
      );
    } catch (error) {
      if (error instanceof Error && error.message === "User was not found") {
        return reply.status(404).send({
          error: "user_not_found",
          message: "User was not found"
        });
      }

      if (
        error instanceof Error &&
        error.message === "User cannot register passkeys unless active"
      ) {
        return reply.status(409).send({
          error: "user_not_active",
          message: "User cannot register passkeys unless active"
        });
      }

      throw error;
    }
  });
}
