import cookie from "@fastify/cookie";
import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import type {
  PasskeyCredential,
  PasskeyCredentialId,
  Session,
  SessionId,
  UserId
} from "../domain/identity.js";
import { registerPasskeyManagementRoutes } from "./passkey-management-routes.js";

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

const passkey: PasskeyCredential = {
  id: "passkey-id" as PasskeyCredentialId,
  userId,
  credentialId: "credential-public-id",
  publicKey: "public-key",
  signCount: 8,
  deviceName: "MacBook Pro",
  lastUsedAt: new Date("2026-06-01T12:30:00.000Z"),
  createdAt: new Date("2026-06-01T12:00:00.000Z"),
  revokedAt: null
};

function createApp(options: {
  authenticatedSession?: Session | null;
  passkeys?: PasskeyCredential[];
}) {
  const app = Fastify();
  void app.register(cookie);
  void registerPasskeyManagementRoutes(app, {
    sessionCookieName: "sceauid_session",
    sessionService: {
      async authenticate(token) {
        expect(token).toBe("session-token");
        return options.authenticatedSession ?? null;
      }
    },
    store: {
      async listPasskeysForUser(listUserId) {
        expect(listUserId).toBe(userId);
        return options.passkeys ?? [];
      }
    }
  });

  return app;
}

describe("passkey management routes", () => {
  it("lists passkeys for the authenticated user", async () => {
    const app = createApp({
      authenticatedSession: session,
      passkeys: [passkey]
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/passkeys",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      passkeys: [
        {
          id: "passkey-id",
          credentialId: "credential-public-id",
          deviceName: "MacBook Pro",
          signCount: 8,
          lastUsedAt: "2026-06-01T12:30:00.000Z",
          createdAt: "2026-06-01T12:00:00.000Z",
          revokedAt: null
        }
      ]
    });
  });

  it("rejects requests without a session cookie", async () => {
    const app = createApp({
      authenticatedSession: session,
      passkeys: [passkey]
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/passkeys"
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({
      error: "unauthenticated",
      message: "Session cookie was not found"
    });
  });

  it("rejects requests with an invalid session", async () => {
    const app = createApp({
      authenticatedSession: null,
      passkeys: [passkey]
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/passkeys",
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
