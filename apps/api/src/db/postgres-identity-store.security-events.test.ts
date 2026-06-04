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

    const page = await context.store.listSecurityEventsForUser({ userId: user.id, limit: 10 });
    const events = page.events;

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

    const page = await context.store.listSecurityEventsForUser({ userId: user.id, limit: 1 });

    expect(page.events).toHaveLength(1);
    expect(page.nextCursor).toBeDefined();
  });

  it("paginates security events with the next cursor", async () => {
    const user = await createTestUser(context);

    await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "signup_started",
      outcome: "pending",
      riskLevel: "low",
      metadata: { page: "last" },
      context: {}
    });
    await new Promise((resolve) => setTimeout(resolve, 5));
    await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "login_failed",
      outcome: "failure",
      riskLevel: "medium",
      metadata: { page: "first" },
      context: {}
    });

    const firstPage = await context.store.listSecurityEventsForUser({
      userId: user.id,
      limit: 1
    });
    const secondPage = await context.store.listSecurityEventsForUser({
      userId: user.id,
      cursor: firstPage.nextCursor,
      limit: 1
    });

    expect(firstPage.events.map((event) => event.eventType)).toEqual(["login_failed"]);
    expect(firstPage.nextCursor).toBeDefined();
    expect(secondPage.events.map((event) => event.eventType)).toEqual(["signup_started"]);
    expect(secondPage.nextCursor).toBeUndefined();
  });

  it("filters listed security events by type", async () => {
    const user = await createTestUser(context);

    await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "login_failed",
      outcome: "failure",
      riskLevel: "medium",
      metadata: {},
      context: {}
    });
    await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "session_revoked",
      outcome: "success",
      riskLevel: "low",
      metadata: {},
      context: {}
    });

    const page = await context.store.listSecurityEventsForUser({
      userId: user.id,
      eventTypes: ["login_failed"],
      limit: 10
    });
    const events = page.events;

    expect(events.map((event) => event.eventType)).toEqual(["login_failed"]);
  });

  it("filters listed security events by outcome and risk level", async () => {
    const user = await createTestUser(context);

    await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "login_failed",
      outcome: "failure",
      riskLevel: "medium",
      metadata: {},
      context: {}
    });
    await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "suspicious_activity_flagged",
      outcome: "pending",
      riskLevel: "high",
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

    const page = await context.store.listSecurityEventsForUser({
      userId: user.id,
      outcomes: ["failure", "pending"],
      riskLevels: ["medium", "high"],
      limit: 10
    });
    const events = page.events;

    expect(events.map((event) => event.eventType).sort()).toEqual([
      "login_failed",
      "suspicious_activity_flagged"
    ]);
  });
});
