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

  it("finds a security event scoped by user", async () => {
    const user = await createTestUser(context);
    const otherUser = await context.store.createUser({ displayName: "Other User" });

    const event = await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "session_revoked",
      outcome: "success",
      riskLevel: "low",
      metadata: {},
      context: {}
    });

    await expect(context.store.findSecurityEventForUser(user.id, event.id)).resolves.toMatchObject({
      id: event.id,
      userId: user.id,
      eventType: "session_revoked"
    });
    await expect(
      context.store.findSecurityEventForUser(otherUser.id, event.id)
    ).resolves.toBeNull();
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

  it("filters listed security events by created-at window", async () => {
    const user = await createTestUser(context);

    await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "signup_started",
      outcome: "pending",
      riskLevel: "low",
      metadata: { side: "before" },
      context: {}
    });
    await new Promise((resolve) => setTimeout(resolve, 10));
    const boundary = new Date();
    await new Promise((resolve) => setTimeout(resolve, 10));
    await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "login_succeeded",
      outcome: "success",
      riskLevel: "low",
      metadata: { side: "after" },
      context: {}
    });

    const afterPage = await context.store.listSecurityEventsForUser({
      userId: user.id,
      createdAfter: boundary,
      limit: 10
    });
    const beforePage = await context.store.listSecurityEventsForUser({
      userId: user.id,
      createdBefore: boundary,
      limit: 10
    });

    expect(afterPage.events.map((event) => event.metadata)).toEqual([{ side: "after" }]);
    expect(beforePage.events.map((event) => event.metadata)).toEqual([{ side: "before" }]);
  });

  it("filters listed security events by actor and session", async () => {
    const user = await createTestUser(context);
    const actor = await context.store.createUser({ displayName: "Actor User" });
    const otherActor = await context.store.createUser({ displayName: "Other Actor" });
    const expiresAt = new Date("2026-07-01T12:00:00.000Z");
    const session = await context.store.createSession({
      userId: user.id,
      tokenHash: "token-hash-1",
      expiresAt
    });
    const otherSession = await context.store.createSession({
      userId: user.id,
      tokenHash: "token-hash-2",
      expiresAt
    });

    await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: actor.id,
      sessionId: session.id,
      eventType: "session_revoked",
      outcome: "success",
      riskLevel: "low",
      metadata: { match: true },
      context: {}
    });
    await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: otherActor.id,
      sessionId: otherSession.id,
      eventType: "session_revoked",
      outcome: "success",
      riskLevel: "low",
      metadata: { match: false },
      context: {}
    });

    const page = await context.store.listSecurityEventsForUser({
      userId: user.id,
      actorUserId: actor.id,
      sessionId: session.id,
      limit: 10
    });

    expect(page.events.map((event) => event.metadata)).toEqual([{ match: true }]);
  });

  it("filters listed security events by trace id", async () => {
    const user = await createTestUser(context);

    await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "login_failed",
      outcome: "failure",
      riskLevel: "medium",
      metadata: { match: true },
      context: { traceId: "trace-match" }
    });
    await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "login_failed",
      outcome: "failure",
      riskLevel: "medium",
      metadata: { match: false },
      context: { traceId: "trace-other" }
    });

    const page = await context.store.listSecurityEventsForUser({
      userId: user.id,
      traceId: "trace-match",
      limit: 10
    });

    expect(page.events.map((event) => event.metadata)).toEqual([{ match: true }]);
  });

  it("deletes old security events in bounded batches", async () => {
    const user = await createTestUser(context);

    await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "login_failed",
      outcome: "failure",
      riskLevel: "medium",
      metadata: { retained: false, batch: 1 },
      context: {}
    });
    await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "session_revoked",
      outcome: "success",
      riskLevel: "low",
      metadata: { retained: false, batch: 2 },
      context: {}
    });
    await new Promise((resolve) => setTimeout(resolve, 10));
    const cutoff = new Date();
    await new Promise((resolve) => setTimeout(resolve, 10));
    await context.store.createSecurityEvent({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "login_succeeded",
      outcome: "success",
      riskLevel: "low",
      metadata: { retained: true },
      context: {}
    });

    await expect(context.store.deleteSecurityEventsBefore(cutoff, 1)).resolves.toBe(1);
    await expect(context.store.deleteSecurityEventsBefore(cutoff, 1)).resolves.toBe(1);
    await expect(context.store.deleteSecurityEventsBefore(cutoff, 1)).resolves.toBe(0);

    const page = await context.store.listSecurityEventsForUser({
      userId: user.id,
      limit: 10
    });

    expect(page.events.map((event) => event.metadata)).toEqual([{ retained: true }]);
  });
});
