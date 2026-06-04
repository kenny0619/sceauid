import { describe, expect, it } from "vitest";
import type { SecurityEvent, SecurityEventId, UserId } from "../domain/identity.js";
import type {
  CreateSecurityEventInput,
  IdentityStore,
  SecurityEventFilter
} from "../domain/storage.js";
import { DefaultSecurityEventService } from "./security-event-service.js";

function createFakeStore() {
  const createdEvents: CreateSecurityEventInput[] = [];
  const findCalls: Array<{ userId: UserId; eventId: SecurityEventId }> = [];
  const listCalls: SecurityEventFilter[] = [];

  const store: Pick<
    IdentityStore,
    "createSecurityEvent" | "findSecurityEventForUser" | "listSecurityEventsForUser"
  > = {
    async createSecurityEvent(input) {
      createdEvents.push(input);

      return {
        id: "event-id" as SecurityEventId,
        createdAt: new Date("2026-06-01T12:00:00.000Z"),
        ...input
      };
    },
    async findSecurityEventForUser(userId, eventId) {
      findCalls.push({ userId, eventId });
      return null;
    },
    async listSecurityEventsForUser(filter) {
      listCalls.push(filter);
      return { events: [] as SecurityEvent[] };
    }
  };

  return { store, createdEvents, findCalls, listCalls };
}

describe("DefaultSecurityEventService", () => {
  it("finds a security event for a user", async () => {
    const { store, findCalls } = createFakeStore();
    const service = new DefaultSecurityEventService(store);
    const userId = "user-id" as UserId;
    const eventId = "event-id" as SecurityEventId;

    await service.findForUser(userId, eventId);

    expect(findCalls).toEqual([{ userId, eventId }]);
  });

  it("records security events with safe defaults", async () => {
    const { store, createdEvents } = createFakeStore();
    const service = new DefaultSecurityEventService(store);

    await service.record({
      eventType: "login_failed",
      outcome: "failure"
    });

    expect(createdEvents[0]).toMatchObject({
      userId: null,
      actorUserId: null,
      sessionId: null,
      eventType: "login_failed",
      outcome: "failure",
      riskLevel: "low",
      metadata: {},
      context: {}
    });
  });

  it("sanitizes metadata and context before persistence", async () => {
    const { store, createdEvents } = createFakeStore();
    const service = new DefaultSecurityEventService(store);

    await service.record({
      eventType: "suspicious_activity_flagged",
      outcome: "pending",
      riskLevel: "high",
      metadata: {
        reason: "unknown-device",
        ignored: undefined
      },
      context: {
        ipHash: "ip-hash",
        userAgent: "test-agent",
        traceId: "trace-id",
        extra: "ignored"
      } as never
    });

    expect(createdEvents[0]?.metadata).toEqual({
      reason: "unknown-device"
    });
    expect(createdEvents[0]?.context).toEqual({
      ipHash: "ip-hash",
      userAgent: "test-agent",
      traceId: "trace-id"
    });
  });

  it("normalizes list limits", async () => {
    const { store, listCalls } = createFakeStore();
    const service = new DefaultSecurityEventService(store);
    const userId = "user-id" as UserId;

    await service.listForUser(userId);
    await service.listForUser(userId, { limit: 0 });
    await service.listForUser(userId, { limit: 500 });
    await service.listForUser(userId, { limit: 10.8 });

    expect(listCalls.map((call) => call.limit)).toEqual([50, 50, 100, 10]);
  });

  it("passes event type filters to storage", async () => {
    const { store, listCalls } = createFakeStore();
    const service = new DefaultSecurityEventService(store);
    const userId = "user-id" as UserId;

    await service.listForUser(userId, {
      eventTypes: ["login_failed", "session_revoked"],
      outcomes: ["failure"],
      riskLevels: ["medium", "high"],
      limit: 25
    });

    expect(listCalls).toEqual([
      {
        userId,
        eventTypes: ["login_failed", "session_revoked"],
        outcomes: ["failure"],
        riskLevels: ["medium", "high"],
        cursor: undefined,
        limit: 25
      }
    ]);
  });

  it("returns an opaque cursor for the next page", async () => {
    const listCalls: SecurityEventFilter[] = [];
    const nextCursor = {
      createdAt: new Date("2026-06-01T12:00:00.000Z"),
      id: "event-id" as SecurityEventId
    };
    const store = {
      async createSecurityEvent(input: CreateSecurityEventInput) {
        return {
          id: "event-id" as SecurityEventId,
          createdAt: nextCursor.createdAt,
          ...input
        };
      },
      async findSecurityEventForUser() {
        return null;
      },
      async listSecurityEventsForUser(filter: SecurityEventFilter) {
        listCalls.push(filter);
        return {
          events: [] as SecurityEvent[],
          nextCursor
        };
      }
    } satisfies Pick<
      IdentityStore,
      "createSecurityEvent" | "findSecurityEventForUser" | "listSecurityEventsForUser"
    >;
    const service = new DefaultSecurityEventService(store);

    const firstPage = await service.listForUser("user-id" as UserId);
    await service.listForUser("user-id" as UserId, { cursor: firstPage.nextCursor });

    expect(firstPage.nextCursor).toBeTypeOf("string");
    expect(listCalls[1]?.cursor).toEqual(nextCursor);
  });
});
