import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import type { PasskeyCredentialId, UserId } from "../domain/identity.js";
import type { PasskeyRegistrationFinishService } from "./passkey-registration-finish-service.js";
import type { PasskeyRegistrationStartService } from "./passkey-registration-start-service.js";
import { registerPasskeyRoutes } from "./passkey-routes.js";

function createApp(services: {
  finish?: PasskeyRegistrationFinishService;
  start?: PasskeyRegistrationStartService;
}) {
  const app = Fastify();
  void registerPasskeyRoutes(app, {
    registrationFinishService: services.finish ?? {
      async finish() {
        throw new Error("Finish service was not configured");
      }
    },
    registrationStartService: services.start ?? {
      async start() {
        throw new Error("Start service was not configured");
      }
    }
  });
  return app;
}

describe("passkey routes", () => {
  it("starts passkey registration", async () => {
    const app = createApp({
      start: {
        async start(input) {
          expect(input).toEqual({
            userId: "user-id",
            userName: "test@example.com",
            userDisplayName: "Test User"
          });

          return {
            registrationId: "registration-id",
            expiresAt: new Date("2026-06-01T12:05:00.000Z"),
            options: {
              rp: {
                name: "SceauID",
                id: "localhost"
              },
              user: {
                id: "dXNlci1pZA",
                name: "test@example.com",
                displayName: "Test User"
              },
              challenge: "public-challenge",
              pubKeyCredParams: []
            }
          };
        }
      }
    });

    const response = await app.inject({
      method: "POST",
      url: "/v1/passkeys/registration/start",
      payload: {
        userId: "user-id",
        userName: "test@example.com",
        userDisplayName: "Test User"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      registrationId: "registration-id",
      expiresAt: "2026-06-01T12:05:00.000Z",
      options: {
        rp: {
          name: "SceauID",
          id: "localhost"
        },
        user: {
          id: "dXNlci1pZA",
          name: "test@example.com",
          displayName: "Test User"
        },
        challenge: "public-challenge",
        pubKeyCredParams: []
      }
    });
  });

  it("rejects invalid request bodies", async () => {
    const app = createApp({
      start: {
        async start() {
          throw new Error("Should not be called");
        }
      }
    });

    const response = await app.inject({
      method: "POST",
      url: "/v1/passkeys/registration/start",
      payload: {
        userName: "test@example.com"
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: "invalid_request"
    });
  });

  it("maps registration start domain errors to HTTP statuses", async () => {
    const missingUserApp = createApp({
      start: {
        async start() {
          throw new Error("User was not found");
        }
      }
    });
    const inactiveUserApp = createApp({
      start: {
        async start() {
          throw new Error("User cannot register passkeys unless active");
        }
      }
    });

    const missingUser = await missingUserApp.inject({
      method: "POST",
      url: "/v1/passkeys/registration/start",
      payload: {
        userId: "user-id",
        userName: "test@example.com"
      }
    });
    const inactiveUser = await inactiveUserApp.inject({
      method: "POST",
      url: "/v1/passkeys/registration/start",
      payload: {
        userId: "user-id",
        userName: "test@example.com"
      }
    });

    expect(missingUser.statusCode).toBe(404);
    expect(inactiveUser.statusCode).toBe(409);
  });

  it("finishes passkey registration", async () => {
    const app = createApp({
      finish: {
        async finish(input) {
          expect(input).toEqual({
            registrationId: "registration-id",
            credential: {
              id: "credential-id",
              rawId: "credential-id",
              response: {
                clientDataJSON: "client-data",
                attestationObject: "attestation-object"
              },
              clientExtensionResults: {},
              type: "public-key"
            },
            deviceName: "MacBook"
          });

          return {
            userId: "user-id" as UserId,
            credential: {
              id: "passkey-id" as PasskeyCredentialId,
              userId: "user-id" as UserId,
              credentialId: "credential-id",
              publicKey: "AQID",
              signCount: 7,
              deviceName: "MacBook",
              lastUsedAt: null,
              createdAt: new Date("2026-06-01T12:00:00.000Z"),
              revokedAt: null
            }
          };
        }
      }
    });

    const response = await app.inject({
      method: "POST",
      url: "/v1/passkeys/registration/finish",
      payload: {
        registrationId: "registration-id",
        credential: {
          id: "credential-id",
          rawId: "credential-id",
          response: {
            clientDataJSON: "client-data",
            attestationObject: "attestation-object"
          },
          clientExtensionResults: {},
          type: "public-key"
        },
        deviceName: "MacBook"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      userId: "user-id",
      credential: {
        id: "passkey-id",
        credentialId: "credential-id",
        deviceName: "MacBook",
        createdAt: "2026-06-01T12:00:00.000Z"
      }
    });
  });

  it("maps registration finish domain errors to HTTP statuses", async () => {
    const createFinishErrorApp = (message: string) =>
      createApp({
        finish: {
          async finish() {
            throw new Error(message);
          }
        }
      });
    const payload = {
      registrationId: "registration-id",
      credential: {
        id: "credential-id",
        rawId: "credential-id",
        response: {
          clientDataJSON: "client-data",
          attestationObject: "attestation-object"
        },
        clientExtensionResults: {},
        type: "public-key"
      }
    };

    const missingChallenge = await createFinishErrorApp(
      "Passkey registration challenge was not found"
    ).inject({
      method: "POST",
      url: "/v1/passkeys/registration/finish",
      payload
    });
    const duplicateCredential = await createFinishErrorApp(
      "Passkey credential already exists"
    ).inject({
      method: "POST",
      url: "/v1/passkeys/registration/finish",
      payload
    });
    const failedVerification = await createFinishErrorApp(
      "Passkey registration verification failed"
    ).inject({
      method: "POST",
      url: "/v1/passkeys/registration/finish",
      payload
    });

    expect(missingChallenge.statusCode).toBe(404);
    expect(duplicateCredential.statusCode).toBe(409);
    expect(failedVerification.statusCode).toBe(400);
  });
});
