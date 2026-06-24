import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import type {
  RequestContext,
  RiskLevel,
  SecurityEvent,
  SecurityEventId,
  SecurityEventOutcome,
  SecurityEventType,
  SessionId,
  UserId
} from "../domain/identity.js";
import { isRecoverySession } from "../sessions/session-kind.js";
import type { SessionService } from "../sessions/session-service.js";
import {
  InvalidSecurityEventCursorError,
  type SecurityEventService
} from "./security-event-service.js";

export type SecurityEventRoutesDependencies = {
  securityEvents: Pick<SecurityEventService, "findForUser" | "listForUser">;
  sessionCookieName: string;
  sessionService: Pick<SessionService, "authenticate">;
};

type SecurityEventRouteParams = {
  eventId: string;
};

const securityEventTypes = [
  "signup_started",
  "email_verified",
  "passkey_registration_started",
  "passkey_registered",
  "passkey_registration_failed",
  "passkey_removed",
  "login_started",
  "login_succeeded",
  "login_failed",
  "session_created",
  "session_revoked",
  "recovery_codes_enrolled",
  "recovery_code_redeemed",
  "recovery_started",
  "recovery_verified",
  "recovery_completed",
  "recovery_cancelled",
  "recovery_delayed",
  "rate_limit_triggered",
  "suspicious_activity_flagged"
] as const satisfies readonly SecurityEventType[];

const securityEventOutcomes = [
  "failure",
  "pending",
  "success"
] as const satisfies readonly SecurityEventOutcome[];

const riskLevels = ["high", "low", "medium"] as const satisfies readonly RiskLevel[];

function multiValueQuerySchema<T extends readonly [string, ...string[]]>(values: T) {
  return z.preprocess((value) => {
    if (value === undefined) {
      return undefined;
    }

    const entries = Array.isArray(value) ? value : [value];

    return entries.flatMap((entry) =>
      typeof entry === "string"
        ? entry
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean)
        : [entry]
    );
  }, z.array(z.enum(values)).optional());
}

const eventTypeQuerySchema = multiValueQuerySchema(securityEventTypes);
const outcomeQuerySchema = multiValueQuerySchema(securityEventOutcomes);
const riskLevelQuerySchema = multiValueQuerySchema(riskLevels);

const dateQuerySchema = z.coerce.date();

const listSecurityEventsQuerySchema = z.object({
  cursor: z.string().min(1).optional(),
  actorUserId: z.string().min(1).optional(),
  sessionId: z.string().min(1).optional(),
  eventType: eventTypeQuerySchema,
  outcome: outcomeQuerySchema,
  riskLevel: riskLevelQuerySchema,
  traceId: z.string().min(1).optional(),
  createdAfter: dateQuerySchema.optional(),
  createdBefore: dateQuerySchema.optional(),
  limit: z.coerce.number().int().positive().max(100).optional()
});

const recoveryEventTypes = [
  "passkey_registration_started",
  "passkey_registered",
  "passkey_registration_failed",
  "session_revoked",
  "recovery_codes_enrolled",
  "recovery_code_redeemed",
  "recovery_started",
  "recovery_verified",
  "recovery_completed",
  "recovery_cancelled",
  "recovery_delayed"
] as const satisfies readonly SecurityEventType[];

function serializeRequestContext(context: RequestContext): RequestContext {
  return {
    ...(typeof context.ipHash === "string" ? { ipHash: context.ipHash } : {}),
    ...(typeof context.userAgent === "string" ? { userAgent: context.userAgent } : {}),
    ...(typeof context.traceId === "string" ? { traceId: context.traceId } : {})
  };
}

function serializeSecurityEvent(event: SecurityEvent) {
  return {
    id: event.id,
    userId: event.userId,
    actorUserId: event.actorUserId,
    sessionId: event.sessionId,
    eventType: event.eventType,
    outcome: event.outcome,
    riskLevel: event.riskLevel,
    metadata: event.metadata,
    context: serializeRequestContext(event.context),
    createdAt: event.createdAt.toISOString()
  };
}

async function authenticateSecurityEventRequest(
  request: FastifyRequest,
  reply: FastifyReply,
  dependencies: SecurityEventRoutesDependencies
) {
  const token = request.cookies[dependencies.sessionCookieName];

  if (!token) {
    void reply.status(401).send({
      error: "unauthenticated",
      message: "Session cookie was not found"
    });
    return null;
  }

  const session = await dependencies.sessionService.authenticate(token);

  if (!session) {
    void reply.status(401).send({
      error: "unauthenticated",
      message: "Session is invalid or expired"
    });
    return null;
  }

  if (isRecoverySession(session)) {
    void reply.status(403).send({
      error: "standard_session_required",
      message: "Recovery sessions cannot access this endpoint"
    });
    return null;
  }

  return session;
}

export async function registerSecurityEventRoutes(
  app: FastifyInstance,
  dependencies: SecurityEventRoutesDependencies
): Promise<void> {
  app.get("/v1/security-events", async (request, reply) => {
    const query = listSecurityEventsQuerySchema.safeParse(request.query);

    if (!query.success) {
      return reply.status(400).send({
        error: "invalid_request",
        message: "Query parameters did not match the security event list schema"
      });
    }

    const session = await authenticateSecurityEventRequest(request, reply, dependencies);
    if (!session) {
      return;
    }

    try {
      const page = await dependencies.securityEvents.listForUser(session.userId, {
        cursor: query.data.cursor,
        actorUserId: query.data.actorUserId as UserId | undefined,
        sessionId: query.data.sessionId as SessionId | undefined,
        eventTypes: query.data.eventType,
        outcomes: query.data.outcome,
        riskLevels: query.data.riskLevel,
        traceId: query.data.traceId,
        createdAfter: query.data.createdAfter,
        createdBefore: query.data.createdBefore,
        limit: query.data.limit
      });

      return reply.send({
        events: page.events.map(serializeSecurityEvent),
        nextCursor: page.nextCursor ?? null
      });
    } catch (error) {
      if (error instanceof InvalidSecurityEventCursorError) {
        return reply.status(400).send({
          error: "invalid_request",
          message: "Security event cursor is invalid"
        });
      }

      throw error;
    }
  });

  app.get("/v1/recovery/events", async (request, reply) => {
    const query = listSecurityEventsQuerySchema.omit({ eventType: true }).safeParse(request.query);

    if (!query.success) {
      return reply.status(400).send({
        error: "invalid_request",
        message: "Query parameters did not match the recovery event list schema"
      });
    }

    const session = await authenticateSecurityEventRequest(request, reply, dependencies);
    if (!session) {
      return;
    }

    try {
      const page = await dependencies.securityEvents.listForUser(session.userId, {
        cursor: query.data.cursor,
        actorUserId: query.data.actorUserId as UserId | undefined,
        sessionId: query.data.sessionId as SessionId | undefined,
        eventTypes: [...recoveryEventTypes],
        outcomes: query.data.outcome,
        riskLevels: query.data.riskLevel,
        traceId: query.data.traceId,
        createdAfter: query.data.createdAfter,
        createdBefore: query.data.createdBefore,
        limit: query.data.limit
      });

      return reply.send({
        events: page.events.map(serializeSecurityEvent),
        nextCursor: page.nextCursor ?? null
      });
    } catch (error) {
      if (error instanceof InvalidSecurityEventCursorError) {
        return reply.status(400).send({
          error: "invalid_request",
          message: "Security event cursor is invalid"
        });
      }

      throw error;
    }
  });

  app.get<{ Params: SecurityEventRouteParams }>(
    "/v1/security-events/:eventId",
    async (request, reply) => {
      const session = await authenticateSecurityEventRequest(request, reply, dependencies);
      if (!session) {
        return;
      }

      const event = await dependencies.securityEvents.findForUser(
        session.userId,
        request.params.eventId as SecurityEventId
      );

      if (!event) {
        return reply.status(404).send({
          error: "security_event_not_found",
          message: "Security event was not found"
        });
      }

      return reply.send({
        event: serializeSecurityEvent(event)
      });
    }
  );
}
