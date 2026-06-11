import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { UserId } from "../domain/identity.js";
import type { RiskStore } from "../domain/storage.js";
import { type RateLimitPolicy, createRateLimitGuard } from "../http/rate-limit-guard.js";
import { type SessionCookieOptions, setSessionCookie } from "../http/session-cookie.js";
import type { PasskeyLoginFinishService } from "./passkey-login-finish-service.js";
import type { PasskeyLoginStartService } from "./passkey-login-start-service.js";
import type { PasskeyRegistrationFinishService } from "./passkey-registration-finish-service.js";
import type { PasskeyRegistrationStartService } from "./passkey-registration-start-service.js";

export type PasskeyRoutesDependencies = {
  loginFinishService: PasskeyLoginFinishService;
  loginStartService: PasskeyLoginStartService;
  rateLimit?: {
    loginStart?: RateLimitPolicy;
    registrationStart?: RateLimitPolicy;
  };
  registrationFinishService: PasskeyRegistrationFinishService;
  registrationStartService: PasskeyRegistrationStartService;
  riskStore?: RiskStore;
  sessionCookie?: SessionCookieOptions;
};

const authenticatorAttachmentSchema = z.enum(["cross-platform", "platform"]);
const authenticatorTransportSchema = z.enum([
  "ble",
  "cable",
  "hybrid",
  "internal",
  "nfc",
  "smart-card",
  "usb"
]);

const startLoginBodySchema = z
  .object({
    userId: z.string().min(1).optional()
  })
  .optional();

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
      transports: z.array(authenticatorTransportSchema).optional(),
      publicKeyAlgorithm: z.number().optional(),
      publicKey: z.string().min(1).optional()
    }),
    authenticatorAttachment: authenticatorAttachmentSchema.optional(),
    clientExtensionResults: z.record(z.unknown()),
    type: z.literal("public-key")
  }),
  deviceName: z.string().min(1).nullable().optional()
});

const finishLoginBodySchema = z.object({
  loginId: z.string().min(1),
  credential: z.object({
    id: z.string().min(1),
    rawId: z.string().min(1),
    response: z.object({
      clientDataJSON: z.string().min(1),
      authenticatorData: z.string().min(1),
      signature: z.string().min(1),
      userHandle: z.string().min(1).optional()
    }),
    authenticatorAttachment: authenticatorAttachmentSchema.optional(),
    clientExtensionResults: z.record(z.unknown()),
    type: z.literal("public-key")
  }),
  deviceLabel: z.string().min(1).nullable().optional()
});

const defaultLoginStartRateLimit = {
  keyPrefix: "passkey_login_start:ip",
  limit: 20,
  windowSeconds: 60
} satisfies RateLimitPolicy;

const defaultRegistrationStartRateLimit = {
  keyPrefix: "passkey_registration_start:ip",
  limit: 10,
  windowSeconds: 60
} satisfies RateLimitPolicy;

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

function resolveLoginStartStatus(error: unknown): number {
  if (!(error instanceof Error)) {
    return 500;
  }

  if (error.message === "User was not found") {
    return 404;
  }

  if (
    error.message === "User cannot start passkey login unless active" ||
    error.message === "User has no active passkeys"
  ) {
    return 409;
  }

  return 500;
}

function resolveLoginFinishStatus(error: unknown): number {
  if (!(error instanceof Error)) {
    return 500;
  }

  if (
    error.message === "Passkey login challenge was not found" ||
    error.message === "Passkey credential was not found" ||
    error.message === "User was not found"
  ) {
    return 404;
  }

  if (error.message === "User cannot finish passkey login unless active") {
    return 409;
  }

  if (
    error.message === "Passkey login verification failed" ||
    error.message === "Passkey login challenge payload is invalid" ||
    error.message === "Passkey login challenge does not match credential owner" ||
    error.message === "Passkey login challenge does not match relying party config"
  ) {
    return 400;
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
  const loginStartRateLimitGuard = dependencies.riskStore
    ? createRateLimitGuard({
        policy: dependencies.rateLimit?.loginStart ?? defaultLoginStartRateLimit,
        riskStore: dependencies.riskStore
      })
    : undefined;
  const registrationStartRateLimitGuard = dependencies.riskStore
    ? createRateLimitGuard({
        policy: dependencies.rateLimit?.registrationStart ?? defaultRegistrationStartRateLimit,
        riskStore: dependencies.riskStore
      })
    : undefined;

  app.post(
    "/v1/passkeys/login/start",
    {
      ...(loginStartRateLimitGuard ? { preHandler: loginStartRateLimitGuard } : {})
    },
    async (request, reply) => {
      const body = startLoginBodySchema.safeParse(request.body);

      if (!body.success) {
        return reply.status(400).send({
          error: "invalid_request",
          message: "Request body did not match the passkey login start schema"
        });
      }

      try {
        const result = await dependencies.loginStartService.start({
          userId: body.data?.userId as UserId | undefined
        });

        return reply.send({
          loginId: result.loginId,
          expiresAt: result.expiresAt.toISOString(),
          options: result.options
        });
      } catch (error) {
        const status = resolveLoginStartStatus(error);

        if (status === 500) {
          throw error;
        }

        return reply.status(status).send({
          error: "login_start_failed",
          message: error instanceof Error ? error.message : "Unable to start passkey login"
        });
      }
    }
  );

  app.post("/v1/passkeys/login/finish", async (request, reply) => {
    const body = finishLoginBodySchema.safeParse(request.body);

    if (!body.success) {
      return reply.status(400).send({
        error: "invalid_request",
        message: "Request body did not match the passkey login finish schema"
      });
    }

    try {
      const result = await dependencies.loginFinishService.finish({
        loginId: body.data.loginId,
        credential: body.data.credential,
        deviceLabel: body.data.deviceLabel,
        context: {
          ...(typeof request.headers["user-agent"] === "string"
            ? { userAgent: request.headers["user-agent"] }
            : {})
        }
      });
      if (dependencies.sessionCookie) {
        setSessionCookie(
          reply,
          dependencies.sessionCookie,
          result.session.token,
          result.session.session.expiresAt
        );
      }

      return reply.send({
        userId: result.userId,
        credential: {
          id: result.credential.id,
          credentialId: result.credential.credentialId,
          signCount: result.credential.signCount,
          lastUsedAt: result.credential.lastUsedAt?.toISOString() ?? null
        },
        session: {
          id: result.session.session.id,
          token: result.session.token,
          expiresAt: result.session.session.expiresAt.toISOString()
        }
      });
    } catch (error) {
      const status = resolveLoginFinishStatus(error);

      if (status === 500) {
        throw error;
      }

      return reply.status(status).send({
        error: "login_finish_failed",
        message: error instanceof Error ? error.message : "Unable to finish passkey login"
      });
    }
  });

  app.post(
    "/v1/passkeys/registration/start",
    {
      ...(registrationStartRateLimitGuard ? { preHandler: registrationStartRateLimitGuard } : {})
    },
    async (request, reply) => {
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
    }
  );

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
