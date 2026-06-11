import cookie from "@fastify/cookie";
import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import type {
  RiskLevel,
  SecurityEvent,
  SecurityEventId,
  SecurityEventOutcome,
  SecurityEventType,
  Session,
  SessionId,
  UserId
} from "../domain/identity.js";
import { registerSecurityEventRoutes } from "./security-event-routes.js";
import type { ListSecurityEventsInput } from "./security-event-service.js";

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

const recoverySession: Session = {
  ...session,
  id: "recovery-session-id" as SessionId,
  deviceLabel: "Recovery session",
  expiresAt: new Date("2026-06-01T12:16:00.000Z")
};

const event: SecurityEvent = {
  id: "event-id" as SecurityEventId,
  userId,
  actorUserId: userId,
  sessionId: session.id,
  eventType: "session_revoked",
  outcome: "success",
  riskLevel: "low",
  metadata: {
    reason: "targeted_revoke"
  },
  context: {
    userAgent: "test-agent"
  },
  createdAt: new Date("2026-06-01T12:01:00.000Z")
};

function createApp(options: {
  authenticatedSession?: Session | null;
  event?: SecurityEvent | null;
  events?: SecurityEvent[];
  findCalls?: Array<{ userId: UserId; eventId: SecurityEventId }>;
  nextCursor?: string;
  listCalls?: Array<{ userId: UserId; input?: ListSecurityEventsInput }>;
}) {
  const app = Fastify();
  void app.register(cookie);
  void registerSecurityEventRoutes(app, {
    securityEvents: {
      async findForUser(userId, eventId) {
        options.findCalls?.push({ userId, eventId });
        return options.event ?? null;
      },
      async listForUser(userId, input) {
        options.listCalls?.push({ userId, input });
        return {
          events: options.events ?? [],
          nextCursor: options.nextCursor
        };
      }
    },
    sessionCookieName: "sceauid_session",
    sessionService: {
      async authenticate(token) {
        expect(token).toBe("session-token");
        return options.authenticatedSession ?? null;
      }
    }
  });

  return app;
}

describe("security event routes", () => {
  it("lists security events for the authenticated user", async () => {
    const listCalls: Array<{ userId: UserId; input?: ListSecurityEventsInput }> = [];
    const app = createApp({
      authenticatedSession: session,
      events: [event],
      listCalls
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/security-events?limit=10",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(listCalls).toEqual([
      {
        userId,
        input: {
          cursor: undefined,
          eventTypes: undefined,
          outcomes: undefined,
          riskLevels: undefined,
          limit: 10
        }
      }
    ]);
    expect(response.json()).toEqual({
      events: [
        {
          id: "event-id",
          userId: "user-id",
          actorUserId: "user-id",
          sessionId: "session-id",
          eventType: "session_revoked",
          outcome: "success",
          riskLevel: "low",
          metadata: {
            reason: "targeted_revoke"
          },
          context: {
            userAgent: "test-agent"
          },
          createdAt: "2026-06-01T12:01:00.000Z"
        }
      ],
      nextCursor: null
    });
  });

  it("returns the next cursor for paginated security events", async () => {
    const listCalls: Array<{ userId: UserId; input?: ListSecurityEventsInput }> = [];
    const app = createApp({
      authenticatedSession: session,
      events: [event],
      nextCursor: "next-page-token",
      listCalls
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/security-events?limit=10&cursor=current-page-token",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(listCalls).toEqual([
      {
        userId,
        input: {
          cursor: "current-page-token",
          eventTypes: undefined,
          outcomes: undefined,
          riskLevels: undefined,
          limit: 10
        }
      }
    ]);
    expect(response.json()).toMatchObject({
      nextCursor: "next-page-token"
    });
  });

  it("returns a security event detail for the authenticated user", async () => {
    const findCalls: Array<{ userId: UserId; eventId: SecurityEventId }> = [];
    const app = createApp({
      authenticatedSession: session,
      event,
      findCalls
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/security-events/event-id",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(findCalls).toEqual([{ userId, eventId: "event-id" as SecurityEventId }]);
    expect(response.json()).toEqual({
      event: {
        id: "event-id",
        userId: "user-id",
        actorUserId: "user-id",
        sessionId: "session-id",
        eventType: "session_revoked",
        outcome: "success",
        riskLevel: "low",
        metadata: {
          reason: "targeted_revoke"
        },
        context: {
          userAgent: "test-agent"
        },
        createdAt: "2026-06-01T12:01:00.000Z"
      }
    });
  });

  it("returns not found when a security event is missing or outside the user", async () => {
    const app = createApp({
      authenticatedSession: session,
      event: null
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/security-events/event-id",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({
      error: "security_event_not_found",
      message: "Security event was not found"
    });
  });

  it("rejects security event detail requests without a session cookie", async () => {
    const app = createApp({
      authenticatedSession: session,
      event
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/security-events/event-id"
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({
      error: "unauthenticated",
      message: "Session cookie was not found"
    });
  });

  it("rejects security event detail requests with an invalid session", async () => {
    const app = createApp({
      authenticatedSession: null,
      event
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/security-events/event-id",
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

  it("filters security events by event type", async () => {
    const listCalls: Array<{ userId: UserId; input?: ListSecurityEventsInput }> = [];
    const app = createApp({
      authenticatedSession: session,
      events: [event],
      listCalls
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/security-events?eventType=login_failed,session_revoked",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(listCalls).toEqual([
      {
        userId,
        input: {
          cursor: undefined,
          eventTypes: ["login_failed", "session_revoked"] satisfies SecurityEventType[],
          limit: undefined
        }
      }
    ]);
  });

  it("filters security events by outcome and risk level", async () => {
    const listCalls: Array<{ userId: UserId; input?: ListSecurityEventsInput }> = [];
    const app = createApp({
      authenticatedSession: session,
      events: [event],
      listCalls
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/security-events?outcome=failure,pending&riskLevel=medium&riskLevel=high",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(listCalls).toEqual([
      {
        userId,
        input: {
          cursor: undefined,
          eventTypes: undefined,
          outcomes: ["failure", "pending"] satisfies SecurityEventOutcome[],
          riskLevels: ["medium", "high"] satisfies RiskLevel[],
          limit: undefined
        }
      }
    ]);
  });

  it("lists recovery events with the recovery event type preset", async () => {
    const listCalls: Array<{ userId: UserId; input?: ListSecurityEventsInput }> = [];
    const app = createApp({
      authenticatedSession: session,
      events: [
        {
          ...event,
          eventType: "recovery_code_redeemed",
          metadata: {
            redeemedAt: "2026-06-01T12:01:00.000Z"
          }
        }
      ],
      listCalls
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/recovery/events?limit=25&outcome=success&riskLevel=medium",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(listCalls).toEqual([
      {
        userId,
        input: {
          cursor: undefined,
          eventTypes: [
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
          ] satisfies SecurityEventType[],
          outcomes: ["success"] satisfies SecurityEventOutcome[],
          riskLevels: ["medium"] satisfies RiskLevel[],
          limit: 25
        }
      }
    ]);
    expect(response.json()).toMatchObject({
      events: [
        {
          eventType: "recovery_code_redeemed",
          metadata: {
            redeemedAt: "2026-06-01T12:01:00.000Z"
          }
        }
      ],
      nextCursor: null
    });
  });

  it("rejects invalid recovery event query parameters", async () => {
    const app = createApp({
      authenticatedSession: session,
      events: [event]
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/recovery/events?outcome=maybe",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({
      error: "invalid_request",
      message: "Query parameters did not match the recovery event list schema"
    });
  });

  it("rejects requests without a session cookie", async () => {
    const app = createApp({
      authenticatedSession: session,
      events: [event]
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/security-events"
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
      events: [event]
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/security-events",
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

  it("rejects security event list requests with a recovery session", async () => {
    const app = createApp({
      authenticatedSession: recoverySession,
      events: [event]
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/security-events",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({
      error: "standard_session_required",
      message: "Recovery sessions cannot access this endpoint"
    });
  });

  it("rejects recovery event list requests with a recovery session", async () => {
    const app = createApp({
      authenticatedSession: recoverySession,
      events: [event]
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/recovery/events",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({
      error: "standard_session_required",
      message: "Recovery sessions cannot access this endpoint"
    });
  });

  it("rejects invalid query parameters", async () => {
    const app = createApp({
      authenticatedSession: session,
      events: [event]
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/security-events?limit=0",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({
      error: "invalid_request",
      message: "Query parameters did not match the security event list schema"
    });
  });

  it("rejects unknown event type filters", async () => {
    const app = createApp({
      authenticatedSession: session,
      events: [event]
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/security-events?eventType=unknown_event",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({
      error: "invalid_request",
      message: "Query parameters did not match the security event list schema"
    });
  });

  it("rejects unknown timeline filters", async () => {
    const app = createApp({
      authenticatedSession: session,
      events: [event]
    });

    const response = await app.inject({
      method: "GET",
      url: "/v1/security-events?outcome=maybe&riskLevel=critical",
      cookies: {
        sceauid_session: "session-token"
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({
      error: "invalid_request",
      message: "Query parameters did not match the security event list schema"
    });
  });
});
