import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type {
  RiskLevel,
  SecurityEvent,
  SecurityEventOutcome,
  SecurityEventType
} from "../domain/identity.js";
import type { SessionService } from "../sessions/session-service.js";
import type { SecurityEventService } from "./security-event-service.js";

export type SecurityEventRoutesDependencies = {
  securityEvents: Pick<SecurityEventService, "listForUser">;
  sessionCookieName: string;
  sessionService: Pick<SessionService, "authenticate">;
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
  "recovery_started",
  "recovery_verified",
  "recovery_completed",
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

const listSecurityEventsQuerySchema = z.object({
  eventType: eventTypeQuerySchema,
  outcome: outcomeQuerySchema,
  riskLevel: riskLevelQuerySchema,
  limit: z.coerce.number().int().positive().max(100).optional()
});

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
    context: event.context,
    createdAt: event.createdAt.toISOString()
  };
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

    const events = await dependencies.securityEvents.listForUser(session.userId, {
      eventTypes: query.data.eventType,
      outcomes: query.data.outcome,
      riskLevels: query.data.riskLevel,
      limit: query.data.limit
    });

    return reply.send({
      events: events.map(serializeSecurityEvent)
    });
  });
}
