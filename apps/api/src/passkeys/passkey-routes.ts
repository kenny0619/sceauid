import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { UserId } from "../domain/identity.js";
import type { PasskeyRegistrationFinishService } from "./passkey-registration-finish-service.js";
import type { PasskeyRegistrationStartService } from "./passkey-registration-start-service.js";

export type PasskeyRoutesDependencies = {
  registrationFinishService: PasskeyRegistrationFinishService;
  registrationStartService: PasskeyRegistrationStartService;
};

const startRegistrationBodySchema = z.object({
  userId: z.string().min(1),
  userName: z.string().min(1),
  userDisplayName: z.string().min(1).nullable().optional()
});

const finishRegistrationBodySchema = z.object({
  registrationId: z.string().min(1),
  credential: z.object({
    id: z.string().min(1),
    rawId: z.string().min(1),
    response: z.object({
      clientDataJSON: z.string().min(1),
      attestationObject: z.string().min(1),
      authenticatorData: z.string().min(1).optional(),
      transports: z
        .array(z.enum(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]))
        .optional(),
      publicKeyAlgorithm: z.number().optional(),
      publicKey: z.string().min(1).optional()
    }),
    authenticatorAttachment: z.enum(["cross-platform", "platform"]).optional(),
    clientExtensionResults: z.record(z.unknown()),
    type: z.literal("public-key")
  }),
  deviceName: z.string().min(1).nullable().optional()
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

function resolveRegistrationFinishStatus(error: unknown): number {
  if (!(error instanceof Error)) {
    return 500;
  }

  if (
    error.message === "Passkey registration challenge was not found" ||
    error.message === "User was not found"
  ) {
    return 404;
  }

  if (
    error.message === "User cannot register passkeys unless active" ||
    error.message === "Passkey credential already exists"
  ) {
    return 409;
  }

  if (
    error.message === "Passkey registration verification failed" ||
    error.message === "Passkey registration challenge payload is invalid" ||
    error.message === "Passkey registration challenge does not match relying party config"
  ) {
    return 400;
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

  app.post("/v1/passkeys/registration/finish", async (request, reply) => {
    const body = finishRegistrationBodySchema.safeParse(request.body);

    if (!body.success) {
      return reply.status(400).send({
        error: "invalid_request",
        message: "Request body did not match the passkey registration finish schema"
      });
    }

    try {
      const result = await dependencies.registrationFinishService.finish({
        registrationId: body.data.registrationId,
        credential: body.data.credential,
        deviceName: body.data.deviceName
      });

      return reply.send({
        userId: result.userId,
        credential: {
          id: result.credential.id,
          credentialId: result.credential.credentialId,
          deviceName: result.credential.deviceName,
          createdAt: result.credential.createdAt.toISOString()
        }
      });
    } catch (error) {
      const status = resolveRegistrationFinishStatus(error);

      if (status === 500) {
        throw error;
      }

      return reply.status(status).send({
        error: "registration_finish_failed",
        message: error instanceof Error ? error.message : "Unable to finish passkey registration"
      });
    }
  });
}
