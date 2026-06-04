import type { FastifyInstance } from "fastify";
import type { PasskeyCredential } from "../domain/identity.js";
import type { IdentityStore } from "../domain/storage.js";
import type { SessionService } from "../sessions/session-service.js";

export type PasskeyManagementRoutesDependencies = {
  sessionCookieName: string;
  sessionService: Pick<SessionService, "authenticate">;
  store: Pick<IdentityStore, "listPasskeysForUser" | "revokePasskeyCredential">;
  now?: () => Date;
};

type PasskeyRouteParams = {
  passkeyId: string;
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
  const now = dependencies.now ?? (() => new Date());

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

  app.delete<{ Params: PasskeyRouteParams }>("/v1/passkeys/:passkeyId", async (request, reply) => {
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
    const passkey = passkeys.find((credential) => credential.id === request.params.passkeyId);

    if (!passkey) {
      return reply.status(404).send({
        error: "passkey_not_found",
        message: "Passkey was not found"
      });
    }

    await dependencies.store.revokePasskeyCredential(passkey.credentialId, now());

    return reply.send({
      ok: true
    });
  });
}
