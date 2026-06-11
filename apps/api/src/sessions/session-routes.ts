import type { FastifyInstance } from "fastify";
import type { Session, UserId } from "../domain/identity.js";
import type { IdentityStore } from "../domain/storage.js";
import type { SecurityEventService } from "../security-events/security-event-service.js";
import { isRecoverySession, sessionKind } from "./session-kind.js";
import type { SessionService } from "./session-service.js";

export type SessionCookieOptions = {
  name: string;
  path?: string;
  sameSite?: "lax" | "none" | "strict";
  secure?: boolean;
};

export type SessionRoutesDependencies = {
  securityEvents?: Pick<SecurityEventService, "record">;
  sessionCookie: SessionCookieOptions;
  sessionService: Pick<SessionService, "authenticate" | "listForUser" | "revoke">;
  store: Pick<IdentityStore, "findUserById">;
};

type SessionRouteParams = {
  sessionId: string;
};

function clearSessionCookie(
  reply: {
    clearCookie(
      name: string,
      options: {
        path: string;
        sameSite: "lax" | "none" | "strict";
        secure: boolean;
      }
    ): unknown;
  },
  sessionCookie: SessionCookieOptions
): void {
  reply.clearCookie(sessionCookie.name, {
    path: sessionCookie.path ?? "/",
    sameSite: sessionCookie.sameSite ?? "lax",
    secure: sessionCookie.secure ?? false
  });
}

function serializeSession(session: Session, currentSessionId: string) {
  return {
    id: session.id,
    current: session.id === currentSessionId,
    kind: sessionKind(session),
    deviceLabel: session.deviceLabel,
    userAgent: session.userAgent,
    expiresAt: session.expiresAt.toISOString(),
    revokedAt: session.revokedAt?.toISOString() ?? null,
    createdAt: session.createdAt.toISOString()
  };
}

async function recordSessionRevoked(
  securityEvents: Pick<SecurityEventService, "record"> | undefined,
  input: {
    actorSessionId: string;
    actorUserId: UserId;
    reason: "current_session_logout" | "targeted_revoke";
    targetSession: Session;
  }
): Promise<void> {
  await securityEvents
    ?.record({
      userId: input.targetSession.userId,
      actorUserId: input.actorUserId,
      sessionId: input.targetSession.id,
      eventType: "session_revoked",
      outcome: "success",
      metadata: {
        actorSessionId: input.actorSessionId,
        reason: input.reason,
        self: input.actorSessionId === input.targetSession.id,
        targetCreatedAt: input.targetSession.createdAt.toISOString(),
        targetDeviceLabel: input.targetSession.deviceLabel,
        targetExpiresAt: input.targetSession.expiresAt.toISOString(),
        targetUserAgent: input.targetSession.userAgent
      }
    })
    .catch(() => undefined);
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

export async function registerSessionRoutes(
  app: FastifyInstance,
  dependencies: SessionRoutesDependencies
): Promise<void> {
  app.get("/v1/sessions", async (request, reply) => {
    const token = request.cookies[dependencies.sessionCookie.name];

    if (!token) {
      return reply.status(401).send({
        error: "unauthenticated",
        message: "Session cookie was not found"
      });
    }

    const currentSession = await dependencies.sessionService.authenticate(token);

    if (!currentSession) {
      return reply.status(401).send({
        error: "unauthenticated",
        message: "Session is invalid or expired"
      });
    }

    if (isRecoverySession(currentSession)) {
      return rejectRecoverySession(reply);
    }

    const sessions = await dependencies.sessionService.listForUser(currentSession.userId);

    return reply.send({
      sessions: sessions.map((session) => serializeSession(session, currentSession.id))
    });
  });

  app.get("/v1/sessions/current", async (request, reply) => {
    const token = request.cookies[dependencies.sessionCookie.name];

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

    const user = await dependencies.store.findUserById(session.userId as UserId);

    if (!user) {
      return reply.status(401).send({
        error: "unauthenticated",
        message: "Session user was not found"
      });
    }

    return reply.send({
      user: {
        id: user.id,
        displayName: user.displayName,
        status: user.status
      },
      session: {
        id: session.id,
        kind: sessionKind(session),
        deviceLabel: session.deviceLabel,
        userAgent: session.userAgent,
        expiresAt: session.expiresAt.toISOString(),
        createdAt: session.createdAt.toISOString()
      }
    });
  });

  app.delete("/v1/sessions/current", async (request, reply) => {
    const token = request.cookies[dependencies.sessionCookie.name];

    if (token) {
      const session = await dependencies.sessionService.authenticate(token);

      if (session) {
        await dependencies.sessionService.revoke(session.id);
        await recordSessionRevoked(dependencies.securityEvents, {
          actorSessionId: session.id,
          actorUserId: session.userId,
          reason: "current_session_logout",
          targetSession: session
        });
      }
    }

    clearSessionCookie(reply, dependencies.sessionCookie);

    return reply.send({
      ok: true
    });
  });

  app.delete<{ Params: SessionRouteParams }>("/v1/sessions/:sessionId", async (request, reply) => {
    const token = request.cookies[dependencies.sessionCookie.name];

    if (!token) {
      return reply.status(401).send({
        error: "unauthenticated",
        message: "Session cookie was not found"
      });
    }

    const currentSession = await dependencies.sessionService.authenticate(token);

    if (!currentSession) {
      return reply.status(401).send({
        error: "unauthenticated",
        message: "Session is invalid or expired"
      });
    }

    if (isRecoverySession(currentSession)) {
      return rejectRecoverySession(reply);
    }

    const sessions = await dependencies.sessionService.listForUser(currentSession.userId);
    const targetSession = sessions.find((session) => session.id === request.params.sessionId);

    if (!targetSession) {
      return reply.status(404).send({
        error: "session_not_found",
        message: "Session was not found"
      });
    }

    await dependencies.sessionService.revoke(targetSession.id);
    await recordSessionRevoked(dependencies.securityEvents, {
      actorSessionId: currentSession.id,
      actorUserId: currentSession.userId,
      reason: "targeted_revoke",
      targetSession
    });

    if (targetSession.id === currentSession.id) {
      clearSessionCookie(reply, dependencies.sessionCookie);
    }

    return reply.send({
      ok: true
    });
  });
}
