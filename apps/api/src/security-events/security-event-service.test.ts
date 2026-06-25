import { describe, expect, it } from "vitest";
import type { SecurityEvent, SecurityEventId, SessionId, UserId } from "../domain/identity.js";
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
  const deleteCalls: Array<{ cutoff: Date; limit: number }> = [];
  const deleteResults: number[] = [];

  const store: Pick<
    IdentityStore,
    | "createSecurityEvent"
    | "findSecurityEventForUser"
    | "listSecurityEventsForUser"
    | "deleteSecurityEventsBefore"
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
    },
    async deleteSecurityEventsBefore(cutoff, limit) {
      deleteCalls.push({ cutoff, limit });
      return deleteResults.shift() ?? 0;
    }
  };

  return { store, createdEvents, findCalls, listCalls, deleteCalls, deleteResults };
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
        actorUserId: undefined,
        sessionId: undefined,
        eventTypes: ["login_failed", "session_revoked"],
        outcomes: ["failure"],
        riskLevels: ["medium", "high"],
        traceId: undefined,
        cursor: undefined,
        limit: 25
      }
    ]);
  });

  it("passes investigation filters to storage", async () => {
    const { store, listCalls } = createFakeStore();
    const service = new DefaultSecurityEventService(store);
    const userId = "user-id" as UserId;
    const actorUserId = "actor-user-id" as UserId;
    const sessionId = "session-id" as SessionId;

    await service.listForUser(userId, {
      actorUserId,
      sessionId,
      traceId: "trace-id",
      limit: 25
    });

    expect(listCalls).toEqual([
      {
        userId,
        actorUserId,
        sessionId,
        eventTypes: undefined,
        outcomes: undefined,
        riskLevels: undefined,
        traceId: "trace-id",
        createdAfter: undefined,
        createdBefore: undefined,
        cursor: undefined,
        limit: 25
      }
    ]);
  });

  it("passes created-at filters to storage", async () => {
    const { store, listCalls } = createFakeStore();
    const service = new DefaultSecurityEventService(store);
    const userId = "user-id" as UserId;
    const createdAfter = new Date("2026-06-01T12:00:00.000Z");
    const createdBefore = new Date("2026-06-02T12:00:00.000Z");

    await service.listForUser(userId, {
      createdAfter,
      createdBefore,
      limit: 25
    });

    expect(listCalls).toEqual([
      {
        userId,
        actorUserId: undefined,
        sessionId: undefined,
        eventTypes: undefined,
        outcomes: undefined,
        riskLevels: undefined,
        traceId: undefined,
        createdAfter,
        createdBefore,
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
      async deleteSecurityEventsBefore() {
        return 0;
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
      | "createSecurityEvent"
      | "findSecurityEventForUser"
      | "listSecurityEventsForUser"
      | "deleteSecurityEventsBefore"
    >;
    const service = new DefaultSecurityEventService(store);

    const firstPage = await service.listForUser("user-id" as UserId);
    await service.listForUser("user-id" as UserId, { cursor: firstPage.nextCursor });

    expect(firstPage.nextCursor).toBeTypeOf("string");
    expect(listCalls[1]?.cursor).toEqual(nextCursor);
  });

  it("prunes old security events in batches until complete", async () => {
    const { store, deleteCalls, deleteResults } = createFakeStore();
    const service = new DefaultSecurityEventService(store);
    const cutoff = new Date("2026-06-01T12:00:00.000Z");
    deleteResults.push(2, 1);

    const result = await service.pruneBefore(cutoff, {
      batchSize: 2,
      maxBatches: 5
    });

    expect(result).toEqual({
      cutoff,
      deletedCount: 3,
      batches: 2,
      complete: true
    });
    expect(deleteCalls).toEqual([
      { cutoff, limit: 2 },
      { cutoff, limit: 2 }
    ]);
  });

  it("marks pruning incomplete when the max batch count is reached", async () => {
    const { store, deleteResults } = createFakeStore();
    const service = new DefaultSecurityEventService(store);
    const cutoff = new Date("2026-06-01T12:00:00.000Z");
    deleteResults.push(2, 2);

    await expect(
      service.pruneBefore(cutoff, {
        batchSize: 2,
        maxBatches: 2
      })
    ).resolves.toEqual({
      cutoff,
      deletedCount: 4,
      batches: 2,
      complete: false
    });
  });

  it("rejects invalid retention cutoffs", async () => {
    const { store } = createFakeStore();
    const service = new DefaultSecurityEventService(store);

    await expect(service.pruneBefore(new Date("invalid"))).rejects.toThrow(
      "Security event retention cutoff is invalid"
    );
  });
});
