import type { FastifyInstance } from "fastify";
import type { PasskeyCredential } from "../domain/identity.js";
import type { IdentityStore } from "../domain/storage.js";
import type { SessionService } from "../sessions/session-service.js";

export type PasskeyManagementRoutesDependencies = {
  sessionCookieName: string;
  sessionService: Pick<SessionService, "authenticate">;
  store: Pick<IdentityStore, "listPasskeysForUser">;
};

function serializePasskey(credential: PasskeyCredential) {
  return {
    id: credential.id,
    credentialId: credential.credentialId,
    deviceName: credential.deviceName,
    signCount: credential.signCount,
    lastUsedAt: credential.lastUsedAt?.toISOString() ?? null,
    createdAt: credential.createdAt.toISOString(),
    revokedAt: credential.revokedAt?.toISOString() ?? null
  };
}

export async function registerPasskeyManagementRoutes(
  app: FastifyInstance,
  dependencies: PasskeyManagementRoutesDependencies
): Promise<void> {
  app.get("/v1/passkeys", async (request, reply) => {
    const token = request.cookies[dependencies.sessionCookieName];

    if (!token) {
      return reply.status(401).send({
        error: "unauthenticated",
        message: "Session cookie was not found"
      });
    }

    const session = await dependencies.sessionService.authenticate(token);

    if (!session) {
      return reply.status(401).send({
        error: "unauthenticated",
        message: "Session is invalid or expired"
      });
    }

    const passkeys = await dependencies.store.listPasskeysForUser(session.userId);

    return reply.send({
      passkeys: passkeys.map(serializePasskey)
    });
  });
}
