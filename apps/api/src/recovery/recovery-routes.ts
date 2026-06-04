import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { RecoveryRequestId, UserId } from "../domain/identity.js";
import type { SessionService } from "../sessions/session-service.js";
import type { RecoveryCodeService } from "./recovery-code-service.js";

export type RecoveryRoutesDependencies = {
  recoveryCodes: RecoveryCodeService;
  sessionCookieName: string;
  sessionService: Pick<SessionService, "authenticate">;
};

const redeemRecoveryCodeBodySchema = z.object({
  code: z.string().min(1),
  userId: z.string().min(1)
});

const recoveryRequestParamsSchema = z.object({
  recoveryRequestId: z.string().min(1)
});

async function authenticateRequest(
  request: { cookies: Record<string, string | undefined> },
  dependencies: Pick<RecoveryRoutesDependencies, "sessionCookieName" | "sessionService">,
  reply: {
    status(statusCode: number): {
      send(payload: { error: string; message: string }): unknown;
    };
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

  return session;
}

export async function registerRecoveryRoutes(
  app: FastifyInstance,
  dependencies: RecoveryRoutesDependencies
): Promise<void> {
  app.get("/v1/recovery/status", async (request, reply) => {
    const session = await authenticateRequest(request, dependencies, reply);

    if (!session) {
      return;
    }

    return reply.send(await dependencies.recoveryCodes.status(session.userId));
  });

  app.post("/v1/recovery/codes", async (request, reply) => {
    const session = await authenticateRequest(request, dependencies, reply);

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
}
