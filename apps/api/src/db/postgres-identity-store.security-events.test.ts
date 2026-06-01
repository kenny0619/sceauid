import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { createPostgresStoreTestContext, createTestUser } from "./postgres-test-harness.js";

const context = createPostgresStoreTestContext();

afterAll(async () => {
  await context.cleanup();
  await context.client.close();
});

beforeEach(async () => {
  await context.cleanup();
});

describe("PostgresIdentityStore security events", () => {
  it("creates security events with metadata and request context", async () => {
    const user = await createTestUser(context);

    const event = await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "login_succeeded",
      outcome: "success",
      riskLevel: "low",
      metadata: { method: "passkey" },
      context: {
        ipHash: "ip-hash",
        userAgent: "test-agent",
        traceId: "trace-id"
      }
    });

    expect(event).toMatchObject({
      userId: user.id,
      actorUserId: user.id,
      eventType: "login_succeeded",
      metadata: { method: "passkey" },
      context: {
        ipHash: "ip-hash",
        userAgent: "test-agent",
        traceId: "trace-id"
      }
    });
  });

  it("lists events newest first and scoped by user", async () => {
    const user = await createTestUser(context);
    const otherUser = await context.store.createUser({ displayName: "Other User" });

    await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "signup_started",
      outcome: "pending",
      riskLevel: "low",
      metadata: { order: "first" },
      context: {}
    });
    await new Promise((resolve) => setTimeout(resolve, 5));
    await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "login_succeeded",
      outcome: "success",
      riskLevel: "low",
      metadata: { order: "second" },
      context: {}
    });
    await context.store.createSecurityEvent({
      userId: otherUser.id,
      actorUserId: otherUser.id,
      sessionId: null,
      eventType: "login_failed",
      outcome: "failure",
      riskLevel: "medium",
      metadata: {},
      context: {}
    });

    const events = await context.store.listSecurityEventsForUser(user.id, 10);

    expect(events).toHaveLength(2);
    expect(events.map((event) => event.eventType)).toEqual(["login_succeeded", "signup_started"]);
  });

  it("respects security event list limits", async () => {
    const user = await createTestUser(context);

    await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "signup_started",
      outcome: "pending",
      riskLevel: "low",
      metadata: {},
      context: {}
    });
    await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "login_succeeded",
      outcome: "success",
      riskLevel: "low",
      metadata: {},
      context: {}
    });

    await expect(context.store.listSecurityEventsForUser(user.id, 1)).resolves.toHaveLength(1);
  });
});
