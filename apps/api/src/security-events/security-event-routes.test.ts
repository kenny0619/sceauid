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
  events?: SecurityEvent[];
  listCalls?: Array<{ userId: UserId; input?: ListSecurityEventsInput }>;
}) {
  const app = Fastify();
  void app.register(cookie);
  void registerSecurityEventRoutes(app, {
    securityEvents: {
      async listForUser(userId, input) {
        options.listCalls?.push({ userId, input });
        return options.events ?? [];
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
        input: { eventTypes: undefined, outcomes: undefined, riskLevels: undefined, limit: 10 }
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
      ]
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
          eventTypes: undefined,
          outcomes: ["failure", "pending"] satisfies SecurityEventOutcome[],
          riskLevels: ["medium", "high"] satisfies RiskLevel[],
          limit: undefined
        }
      }
    ]);
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
