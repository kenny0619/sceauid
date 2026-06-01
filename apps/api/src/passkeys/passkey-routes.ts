import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { UserId } from "../domain/identity.js";
import type { PasskeyRegistrationStartService } from "./passkey-registration-start-service.js";

export type PasskeyRoutesDependencies = {
  registrationStartService: PasskeyRegistrationStartService;
};

const startRegistrationBodySchema = z.object({
  userId: z.string().min(1),
  userName: z.string().min(1),
  userDisplayName: z.string().min(1).nullable().optional()
});

function resolveRegistrationStartStatus(error: unknown): number {
  if (!(error instanceof Error)) {
    return 500;
  }

  if (error.message === "User was not found") {
    return 404;
  }

  if (error.message === "User cannot register passkeys unless active") {
    return 409;
  }

  return 500;
}

export async function registerPasskeyRoutes(
  app: FastifyInstance,
  dependencies: PasskeyRoutesDependencies
): Promise<void> {
  app.post("/v1/passkeys/registration/start", async (request, reply) => {
    const body = startRegistrationBodySchema.safeParse(request.body);

    if (!body.success) {
      return reply.status(400).send({
        error: "invalid_request",
        message: "Request body did not match the passkey registration start schema"
      });
    }

    try {
      const result = await dependencies.registrationStartService.start({
        userId: body.data.userId as UserId,
        userName: body.data.userName,
        userDisplayName: body.data.userDisplayName
      });

      return reply.send({
        registrationId: result.registrationId,
        expiresAt: result.expiresAt.toISOString(),
        options: result.options
      });
    } catch (error) {
      const status = resolveRegistrationStartStatus(error);

      if (status === 500) {
        throw error;
      }

      return reply.status(status).send({
        error: "registration_start_failed",
        message: error instanceof Error ? error.message : "Unable to start passkey registration"
      });
    }
  });
}
