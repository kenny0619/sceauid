import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { SecurityEvent } from "../domain/identity.js";
import type { SessionService } from "../sessions/session-service.js";
import type { SecurityEventService } from "./security-event-service.js";

export type SecurityEventRoutesDependencies = {
  securityEvents: Pick<SecurityEventService, "listForUser">;
  sessionCookieName: string;
  sessionService: Pick<SessionService, "authenticate">;
};

const listSecurityEventsQuerySchema = z.object({
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

    const events = await dependencies.securityEvents.listForUser(session.userId, query.data.limit);

    return reply.send({
      events: events.map(serializeSecurityEvent)
    });
  });
}
