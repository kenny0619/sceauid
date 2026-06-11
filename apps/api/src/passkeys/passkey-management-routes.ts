import type { FastifyInstance } from "fastify";
import type { PasskeyCredential, SessionId, UserId } from "../domain/identity.js";
import type { IdentityStore } from "../domain/storage.js";
import type { SecurityEventService } from "../security-events/security-event-service.js";
import { isFreshAuthentication, rejectFreshAuthRequired } from "../sessions/fresh-auth.js";
import { isRecoverySession } from "../sessions/session-kind.js";
import type { SessionService } from "../sessions/session-service.js";

export type PasskeyManagementRoutesDependencies = {
  securityEvents?: Pick<SecurityEventService, "record">;
  sessionCookieName: string;
  sessionService: Pick<SessionService, "authenticate">;
  store: Pick<IdentityStore, "listPasskeysForUser" | "revokePasskeyCredential">;
  freshAuthWindowSeconds?: number;
  now?: () => Date;
};

type PasskeyRouteParams = {
  passkeyId: string;
};

function activePasskeyCount(passkeys: PasskeyCredential[]): number {
  return passkeys.filter((credential) => credential.revokedAt === null).length;
}

async function recordPasskeyRemoved(
  securityEvents: Pick<SecurityEventService, "record"> | undefined,
  input: {
    actorSessionId: SessionId;
    actorUserId: UserId;
    passkey: PasskeyCredential;
    revokedAt: Date;
  }
): Promise<void> {
  await securityEvents
    ?.record({
      userId: input.passkey.userId,
      actorUserId: input.actorUserId,
      sessionId: input.actorSessionId,
      eventType: "passkey_removed",
      outcome: "success",
      metadata: {
        actorSessionId: input.actorSessionId,
        deviceName: input.passkey.deviceName,
        passkeyId: input.passkey.id,
        revokedAt: input.revokedAt.toISOString()
      }
    })
    .catch(() => undefined);
}

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

function rejectRecoverySession(reply: {
  status(statusCode: number): {
    send(payload: { error: string; message: string }): unknown;
  };
}) {
  return reply.status(403).send({
    error: "standard_session_required",
    message: "Recovery sessions cannot access this endpoint"
  });
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

    if (isRecoverySession(session)) {
      return rejectRecoverySession(reply);
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

    if (isRecoverySession(session)) {
      return rejectRecoverySession(reply);
    }

    if (
      !isFreshAuthentication(session, now(), {
        windowSeconds: dependencies.freshAuthWindowSeconds
      })
    ) {
      return rejectFreshAuthRequired(reply);
    }

    const passkeys = await dependencies.store.listPasskeysForUser(session.userId);
    const passkey = passkeys.find((credential) => credential.id === request.params.passkeyId);

    if (!passkey) {
      return reply.status(404).send({
        error: "passkey_not_found",
        message: "Passkey was not found"
      });
    }

    if (passkey.revokedAt === null && activePasskeyCount(passkeys) <= 1) {
      return reply.status(409).send({
        error: "last_passkey_required",
        message: "At least one active passkey must remain on the account"
      });
    }

    const revokedAt = now();

    await dependencies.store.revokePasskeyCredential(passkey.credentialId, revokedAt);
    await recordPasskeyRemoved(dependencies.securityEvents, {
      actorSessionId: session.id,
      actorUserId: session.userId,
      passkey,
      revokedAt
    });

    return reply.send({
      ok: true
    });
  });
}
