import cookie from "@fastify/cookie";
import Fastify from "fastify";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { createPostgresStoreTestContext, createTestUser } from "../db/postgres-test-harness.js";
import { DefaultSecurityEventService } from "../security-events/security-event-service.js";
import { registerSessionRoutes } from "./session-routes.js";
import { DefaultSessionService } from "./session-service.js";
import type { SessionToken } from "./session-token.js";

const context = createPostgresStoreTestContext();
const now = new Date("2026-06-01T12:00:00.000Z");

afterAll(async () => {
  await context.cleanup();
  await context.client.close();
});

beforeEach(async () => {
  await context.cleanup();
});

describe("session routes integration", () => {
  it("persists security events for targeted session revokes", async () => {
    const user = await createTestUser(context);
    const tokens = ["current-session-token", "other-session-token"] as SessionToken[];
    const sessionService = new DefaultSessionService(context.store, {
      now: () => now,
      generateToken: () => {
        const token = tokens.shift();

        if (!token) {
          throw new Error("Expected session token");
        }

        return token;
      }
    });
    const securityEvents = new DefaultSecurityEventService(context.store);
    const current = await sessionService.create({
      userId: user.id,
      deviceLabel: "Safari on macOS"
    });
    const other = await sessionService.create({
      userId: user.id,
      deviceLabel: "Chrome on Windows"
    });
    const app = Fastify();
    await app.register(cookie);
    await registerSessionRoutes(app, {
      securityEvents,
      sessionCookie: {
        name: "sceauid_session"
      },
      sessionService,
      store: context.store
    });

    const response = await app.inject({
      method: "DELETE",
      url: `/v1/sessions/${other.session.id}`,
      cookies: {
        sceauid_session: current.token
      }
    });

    expect(response.statusCode).toBe(200);
    const page = await securityEvents.listForUser(user.id);

    expect(page.events).toHaveLength(1);
    expect(page.events[0]).toMatchObject({
      userId: user.id,
      actorUserId: user.id,
      sessionId: other.session.id,
      eventType: "session_revoked",
      outcome: "success",
      metadata: {
        actorSessionId: current.session.id,
        reason: "targeted_revoke",
        self: false
      }
    });
  });
});
