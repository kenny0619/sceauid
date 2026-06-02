import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import type { PasskeyCredentialId, SessionId, UserId } from "../domain/identity.js";
import type { PasskeyLoginFinishService } from "./passkey-login-finish-service.js";
import type { PasskeyLoginStartService } from "./passkey-login-start-service.js";
import type { PasskeyRegistrationFinishService } from "./passkey-registration-finish-service.js";
import type { PasskeyRegistrationStartService } from "./passkey-registration-start-service.js";
import { registerPasskeyRoutes } from "./passkey-routes.js";
import type { SessionToken } from "../sessions/session-token.js";

function createApp(services: {
  finish?: PasskeyRegistrationFinishService;
  loginFinish?: PasskeyLoginFinishService;
  loginStart?: PasskeyLoginStartService;
  start?: PasskeyRegistrationStartService;
}) {
  const app = Fastify();
  void registerPasskeyRoutes(app, {
    loginFinishService: services.loginFinish ?? {
      async finish() {
        throw new Error("Login finish service was not configured");
      }
    },
    loginStartService: services.loginStart ?? {
      async start() {
        throw new Error("Login start service was not configured");
      }
    },
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
  it("starts passkey login", async () => {
    const app = createApp({
      loginStart: {
        async start(input) {
          expect(input).toEqual({ userId: "user-id" });

          return {
            loginId: "login-id",
            expiresAt: new Date("2026-06-01T12:05:00.000Z"),
            options: {
              challenge: "public-challenge",
              rpId: "localhost",
              allowCredentials: [
                {
                  id: "credential-id",
                  type: "public-key"
                }
              ],
              timeout: 300_000,
              userVerification: "preferred"
            }
          };
        }
      }
    });

    const response = await app.inject({
      method: "POST",
      url: "/v1/passkeys/login/start",
      payload: {
        userId: "user-id"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      loginId: "login-id",
      expiresAt: "2026-06-01T12:05:00.000Z",
      options: {
        challenge: "public-challenge",
        rpId: "localhost",
        allowCredentials: [
          {
            id: "credential-id",
            type: "public-key"
          }
        ],
        timeout: 300_000,
        userVerification: "preferred"
      }
    });
  });

  it("maps login start domain errors to HTTP statuses", async () => {
    const createLoginErrorApp = (message: string) =>
      createApp({
        loginStart: {
          async start() {
            throw new Error(message);
          }
        }
      });

    const missingUser = await createLoginErrorApp("User was not found").inject({
      method: "POST",
      url: "/v1/passkeys/login/start",
      payload: {
        userId: "user-id"
      }
    });
    const inactiveUser = await createLoginErrorApp(
      "User cannot start passkey login unless active"
    ).inject({
      method: "POST",
      url: "/v1/passkeys/login/start",
      payload: {
        userId: "user-id"
      }
    });
    const passkeylessUser = await createLoginErrorApp("User has no active passkeys").inject({
      method: "POST",
      url: "/v1/passkeys/login/start",
      payload: {
        userId: "user-id"
      }
    });

    expect(missingUser.statusCode).toBe(404);
    expect(inactiveUser.statusCode).toBe(409);
    expect(passkeylessUser.statusCode).toBe(409);
  });

  it("finishes passkey login", async () => {
    const app = createApp({
      loginFinish: {
        async finish(input) {
          expect(input).toEqual({
            loginId: "login-id",
            credential: {
              id: "credential-id",
              rawId: "credential-id",
              response: {
                clientDataJSON: "client-data",
                authenticatorData: "authenticator-data",
                signature: "signature"
              },
              clientExtensionResults: {},
              type: "public-key"
            },
            deviceLabel: "Safari on macOS",
            context: {
              userAgent: "test-agent"
            }
          });

          return {
            userId: "user-id" as UserId,
            credential: {
              id: "passkey-id" as PasskeyCredentialId,
              userId: "user-id" as UserId,
              credentialId: "credential-id",
              publicKey: "AQID",
              signCount: 8,
              deviceName: "MacBook",
              lastUsedAt: new Date("2026-06-01T12:00:00.000Z"),
              createdAt: new Date("2026-05-31T12:00:00.000Z"),
              revokedAt: null
            },
            session: {
              token: "session-token" as SessionToken,
              session: {
                id: "session-id" as SessionId,
                userId: "user-id" as UserId,
                tokenHash: "token-hash",
                deviceLabel: "Safari on macOS",
                userAgent: "test-agent",
                ipHash: null,
                expiresAt: new Date("2026-07-01T12:00:00.000Z"),
                revokedAt: null,
                createdAt: new Date("2026-06-01T12:00:00.000Z")
              }
            }
          };
        }
      }
    });

    const response = await app.inject({
      method: "POST",
      url: "/v1/passkeys/login/finish",
      headers: {
        "user-agent": "test-agent"
      },
      payload: {
        loginId: "login-id",
        credential: {
          id: "credential-id",
          rawId: "credential-id",
          response: {
            clientDataJSON: "client-data",
            authenticatorData: "authenticator-data",
            signature: "signature"
          },
          clientExtensionResults: {},
          type: "public-key"
        },
        deviceLabel: "Safari on macOS"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      userId: "user-id",
      credential: {
        id: "passkey-id",
        credentialId: "credential-id",
        signCount: 8,
        lastUsedAt: "2026-06-01T12:00:00.000Z"
      },
      session: {
        id: "session-id",
        token: "session-token",
        expiresAt: "2026-07-01T12:00:00.000Z"
      }
    });
  });

  it("maps login finish domain errors to HTTP statuses", async () => {
    const createLoginFinishErrorApp = (message: string) =>
      createApp({
        loginFinish: {
          async finish() {
            throw new Error(message);
          }
        }
      });
    const payload = {
      loginId: "login-id",
      credential: {
        id: "credential-id",
        rawId: "credential-id",
        response: {
          clientDataJSON: "client-data",
          authenticatorData: "authenticator-data",
          signature: "signature"
        },
        clientExtensionResults: {},
        type: "public-key"
      }
    };

    const missingChallenge = await createLoginFinishErrorApp(
      "Passkey login challenge was not found"
    ).inject({
      method: "POST",
      url: "/v1/passkeys/login/finish",
      payload
    });
    const inactiveUser = await createLoginFinishErrorApp(
      "User cannot finish passkey login unless active"
    ).inject({
      method: "POST",
      url: "/v1/passkeys/login/finish",
      payload
    });
    const failedVerification = await createLoginFinishErrorApp(
      "Passkey login verification failed"
    ).inject({
      method: "POST",
      url: "/v1/passkeys/login/finish",
      payload
    });

    expect(missingChallenge.statusCode).toBe(404);
    expect(inactiveUser.statusCode).toBe(409);
    expect(failedVerification.statusCode).toBe(400);
  });

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
