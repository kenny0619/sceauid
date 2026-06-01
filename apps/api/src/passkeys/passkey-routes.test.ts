import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import type { PasskeyRegistrationStartService } from "./passkey-registration-start-service.js";
import { registerPasskeyRoutes } from "./passkey-routes.js";

function createApp(service: PasskeyRegistrationStartService) {
  const app = Fastify();
  void registerPasskeyRoutes(app, { registrationStartService: service });
  return app;
}

describe("passkey routes", () => {
  it("starts passkey registration", async () => {
    const app = createApp({
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
      async start() {
        throw new Error("Should not be called");
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
      async start() {
        throw new Error("User was not found");
      }
    });
    const inactiveUserApp = createApp({
      async start() {
        throw new Error("User cannot register passkeys unless active");
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
});
