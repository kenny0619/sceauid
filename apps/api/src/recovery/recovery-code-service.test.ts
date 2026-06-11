import { describe, expect, it } from "vitest";
import type {
  RecoveryRequest,
  RecoveryRequestId,
  Session,
  SessionId,
  UserId
} from "../domain/identity.js";
import type {
  CreateRecoveryCodeInput,
  CreateRecoveryRequestInput,
  IdentityStore,
  RiskStore
} from "../domain/storage.js";
import type { SecurityEventService } from "../security-events/security-event-service.js";
import type { SessionService } from "../sessions/session-service.js";
import type { SessionToken } from "../sessions/session-token.js";
import {
  DefaultRecoveryCodeService,
  hashRecoveryCode,
  normalizeRecoveryCode
} from "./recovery-code-service.js";

const userId = "user-id" as UserId;
const sessionId = "session-id" as SessionId;
const recoverySessionId = "recovery-session-id" as SessionId;
const recoveryRequestId = "recovery-request-id" as RecoveryRequestId;
const recoverySessionToken = "recovery-session-token" as SessionToken;

function createFakeStore(options: { unusedRecoveryCodeCount?: number } = {}) {
  const consumedCodes: Array<{ codeHash: string; usedAt: Date; userId: UserId }> = [];
  const createdCodes: CreateRecoveryCodeInput[] = [];
  const createdRecoveryRequests: CreateRecoveryRequestInput[] = [];
  const markedUsed: Array<{ userId: UserId; usedAt: Date }> = [];
  const recordedEvents: Array<Parameters<SecurityEventService["record"]>[0]> = [];
  const createdSessions: Array<Parameters<SessionService["create"]>[0]> = [];
  const rateLimitChecks: Array<{ key: string; limit: number; windowSeconds: number }> = [];
  let consumeRecoveryCodeResult = true;
  let rateLimitAllowed = true;
  let recoveryRequest: RecoveryRequest | null = {
    id: recoveryRequestId,
    userId,
    status: "pending",
    riskLevel: "medium",
    expiresAt: new Date("2026-06-01T12:05:00.000Z"),
    completedAt: null,
    createdAt: new Date("2026-06-01T12:00:00.000Z")
  };

  const store: Pick<
    IdentityStore,
    | "completeActiveRecoveryRequest"
    | "cancelActiveRecoveryRequest"
    | "consumeRecoveryCode"
    | "countUnusedRecoveryCodesForUser"
    | "createRecoveryRequest"
    | "createRecoveryCode"
    | "findRecoveryRequestById"
    | "markUnusedRecoveryCodesUsed"
  > = {
    async cancelActiveRecoveryRequest(requestId, cancelledAt) {
      expect(requestId).toBe(recoveryRequestId);

      if (
        !recoveryRequest ||
        recoveryRequest.status !== "pending" ||
        recoveryRequest.expiresAt <= cancelledAt
      ) {
        return null;
      }

      recoveryRequest = {
        ...recoveryRequest,
        status: "cancelled"
      };

      return recoveryRequest;
    },
    async completeActiveRecoveryRequest(requestId, completedAt) {
      expect(requestId).toBe(recoveryRequestId);

      if (
        !recoveryRequest ||
        recoveryRequest.status !== "pending" ||
        recoveryRequest.expiresAt <= completedAt
      ) {
        return null;
      }

      recoveryRequest = {
        ...recoveryRequest,
        status: "completed",
        completedAt
      };

      return recoveryRequest;
    },
    async consumeRecoveryCode(consumeUserId, codeHash, usedAt) {
      consumedCodes.push({ codeHash, usedAt, userId: consumeUserId });
      return consumeRecoveryCodeResult;
    },
    async countUnusedRecoveryCodesForUser(statusUserId) {
      expect(statusUserId).toBe(userId);
      return options.unusedRecoveryCodeCount ?? 0;
    },
    async createRecoveryCode(input) {
      createdCodes.push(input);
      return undefined as never;
    },
    async createRecoveryRequest(input) {
      createdRecoveryRequests.push(input);
      return {
        id: recoveryRequestId,
        userId: input.userId,
        status: "pending",
        riskLevel: input.riskLevel,
        expiresAt: input.expiresAt,
        completedAt: null,
        createdAt: new Date("2026-06-01T12:00:00.000Z")
      };
    },
    async findRecoveryRequestById(requestId) {
      expect(requestId).toBe(recoveryRequestId);
      return recoveryRequest;
    },
    async markUnusedRecoveryCodesUsed(markUserId, usedAt) {
      markedUsed.push({ userId: markUserId, usedAt });
    }
  };

  const securityEvents: SecurityEventService = {
    async findForUser() {
      return null;
    },
    async listForUser() {
      return {
        events: []
      };
    },
    async record(input) {
      recordedEvents.push(input);
      return undefined as never;
    }
  };

  const sessionService: Pick<SessionService, "create"> = {
    async create(input) {
      createdSessions.push(input);

      const session: Session = {
        id: recoverySessionId,
        userId: input.userId,
        tokenHash: "token-hash",
        deviceLabel: input.deviceLabel ?? null,
        userAgent: input.context?.userAgent ?? null,
        ipHash: input.context?.ipHash ?? null,
        expiresAt: new Date("2026-06-01T12:16:00.000Z"),
        revokedAt: null,
        authenticatedAt: new Date("2026-06-01T12:01:00.000Z"),
        createdAt: new Date("2026-06-01T12:01:00.000Z")
      };

      return {
        session,
        token: recoverySessionToken
      };
    }
  };

  const riskStore: RiskStore = {
    async checkRateLimit(key, limit, windowSeconds) {
      rateLimitChecks.push({ key, limit, windowSeconds });

      return {
        allowed: rateLimitAllowed,
        limit,
        remaining: rateLimitAllowed ? limit - 1 : 0,
        resetAt: new Date("2026-06-01T12:15:00.000Z")
      };
    }
  };

  return {
    consumedCodes,
    createdCodes,
    createdRecoveryRequests,
    createdSessions,
    markRecoveryCodeInvalid() {
      consumeRecoveryCodeResult = false;
    },
    markRateLimited() {
      rateLimitAllowed = false;
    },
    markRecoveryRequestMissing() {
      recoveryRequest = null;
    },
    markRecoveryRequestCompleted() {
      if (recoveryRequest) {
        recoveryRequest = {
          ...recoveryRequest,
          status: "completed",
          completedAt: new Date("2026-06-01T12:01:00.000Z")
        };
      }
    },
    markRecoveryRequestExpired() {
      if (recoveryRequest) {
        recoveryRequest = {
          ...recoveryRequest,
          expiresAt: new Date("2026-06-01T11:59:00.000Z")
        };
      }
    },
    markedUsed,
    rateLimitChecks,
    recordedEvents,
    riskStore,
    securityEvents,
    sessionService,
    store
  };
}

describe("DefaultRecoveryCodeService", () => {
  it("normalizes and hashes recovery codes", () => {
    expect(normalizeRecoveryCode("abcd-1234 ef")).toBe("ABCD1234EF");
    expect(hashRecoveryCode("ABCD-1234")).toBe(hashRecoveryCode("abcd 1234"));
  });

  it("rotates unused recovery codes and returns the new codes once", async () => {
    const { createdCodes, markedUsed, recordedEvents, securityEvents, sessionService, store } =
      createFakeStore();
    let byte = 0;
    const service = new DefaultRecoveryCodeService(store, sessionService, {
      codeCount: 2,
      now: () => new Date("2026-06-01T12:00:00.000Z"),
      randomBytes(size) {
        const buffer = Buffer.alloc(size, byte);
        byte += 1;
        return buffer;
      },
      securityEvents
    });

    const result = await service.enroll({ actorSessionId: sessionId, userId });

    expect(result).toEqual({
      codes: ["00000-00000-00000-00000", "01010-10101-01010-10101"],
      recoveryCodesConfigured: true,
      unusedRecoveryCodeCount: 2
    });
    expect(markedUsed).toEqual([{ userId, usedAt: new Date("2026-06-01T12:00:00.000Z") }]);
    expect(createdCodes).toEqual([
      {
        userId,
        codeHash: hashRecoveryCode("00000-00000-00000-00000")
      },
      {
        userId,
        codeHash: hashRecoveryCode("01010-10101-01010-10101")
      }
    ]);
    expect(recordedEvents).toEqual([
      {
        actorUserId: userId,
        eventType: "recovery_codes_enrolled",
        metadata: {
          codeCount: 2,
          enrolledAt: "2026-06-01T12:00:00.000Z"
        },
        outcome: "success",
        sessionId,
        userId
      }
    ]);
  });

  it("returns recovery code enrollment status without codes", async () => {
    const { sessionService, store } = createFakeStore({ unusedRecoveryCodeCount: 3 });
    const service = new DefaultRecoveryCodeService(store, sessionService);

    await expect(service.status(userId)).resolves.toEqual({
      recoveryCodesConfigured: true,
      unusedRecoveryCodeCount: 3
    });
  });

  it("redeems a recovery code using its normalized hash", async () => {
    const {
      consumedCodes,
      createdRecoveryRequests,
      rateLimitChecks,
      recordedEvents,
      riskStore,
      securityEvents,
      sessionService,
      store
    } = createFakeStore();
    const service = new DefaultRecoveryCodeService(store, sessionService, {
      now: () => new Date("2026-06-01T12:00:00.000Z"),
      recoveryRequestTtlSeconds: 300,
      riskStore,
      securityEvents
    });

    await expect(service.redeem({ code: "abcd-1234 ef", userId })).resolves.toEqual({
      ok: true,
      recoveryRequest: {
        id: recoveryRequestId,
        expiresAt: new Date("2026-06-01T12:05:00.000Z"),
        riskLevel: "medium"
      }
    });

    expect(consumedCodes).toEqual([
      {
        codeHash: hashRecoveryCode("ABCD1234EF"),
        usedAt: new Date("2026-06-01T12:00:00.000Z"),
        userId
      }
    ]);
    expect(rateLimitChecks).toEqual([
      {
        key: "recovery-code-redemption:user:user-id",
        limit: 5,
        windowSeconds: 900
      }
    ]);
    expect(createdRecoveryRequests).toEqual([
      {
        userId,
        riskLevel: "medium",
        expiresAt: new Date("2026-06-01T12:05:00.000Z")
      }
    ]);
    expect(recordedEvents).toEqual([
      {
        actorUserId: userId,
        eventType: "recovery_code_redeemed",
        metadata: {
          recoveryRequestId,
          redeemedAt: "2026-06-01T12:00:00.000Z",
          scope: "recovery_code_redemption"
        },
        outcome: "success",
        riskLevel: "medium",
        userId
      }
    ]);
  });

  it("rejects invalid or used recovery codes", async () => {
    const { markRecoveryCodeInvalid, recordedEvents, securityEvents, sessionService, store } =
      createFakeStore();
    markRecoveryCodeInvalid();
    const service = new DefaultRecoveryCodeService(store, sessionService, {
      now: () => new Date("2026-06-01T12:00:00.000Z"),
      securityEvents
    });

    await expect(service.redeem({ code: "invalid-code", userId })).rejects.toThrow(
      "Recovery code was invalid or already used"
    );
    expect(recordedEvents).toEqual([
      {
        actorUserId: userId,
        eventType: "recovery_code_redeemed",
        metadata: {
          attemptedAt: "2026-06-01T12:00:00.000Z",
          reason: "invalid_or_used",
          scope: "recovery_code_redemption"
        },
        outcome: "failure",
        riskLevel: "medium",
        userId
      }
    ]);
  });

  it("rejects recovery code redemption when rate limited", async () => {
    const {
      consumedCodes,
      markRateLimited,
      rateLimitChecks,
      recordedEvents,
      riskStore,
      securityEvents,
      sessionService,
      store
    } = createFakeStore();
    markRateLimited();
    const service = new DefaultRecoveryCodeService(store, sessionService, {
      now: () => new Date("2026-06-01T12:00:00.000Z"),
      redemptionRateLimit: {
        limit: 2,
        windowSeconds: 60
      },
      riskStore,
      securityEvents
    });

    await expect(service.redeem({ code: "AAAAA-BBBBB", userId })).rejects.toThrow(
      "Recovery code redemption rate limit exceeded"
    );

    expect(consumedCodes).toEqual([]);
    expect(rateLimitChecks).toEqual([
      {
        key: "recovery-code-redemption:user:user-id",
        limit: 2,
        windowSeconds: 60
      }
    ]);
    expect(recordedEvents).toEqual([
      {
        actorUserId: userId,
        eventType: "rate_limit_triggered",
        metadata: {
          attemptedAt: "2026-06-01T12:00:00.000Z",
          limit: 2,
          remaining: 0,
          resetAt: "2026-06-01T12:15:00.000Z",
          scope: "recovery_code_redemption",
          windowSeconds: 60
        },
        outcome: "failure",
        riskLevel: "medium",
        userId
      }
    ]);
  });

  it("returns recovery request status", async () => {
    const { sessionService, store } = createFakeStore();
    const service = new DefaultRecoveryCodeService(store, sessionService, {
      now: () => new Date("2026-06-01T12:00:00.000Z")
    });

    await expect(service.recoveryRequestStatus(recoveryRequestId)).resolves.toEqual({
      recoveryRequest: {
        id: recoveryRequestId,
        active: true,
        expiresAt: new Date("2026-06-01T12:05:00.000Z"),
        riskLevel: "medium",
        status: "pending"
      }
    });
  });

  it("reports expired pending recovery requests as inactive", async () => {
    const { sessionService, store } = createFakeStore();
    const service = new DefaultRecoveryCodeService(store, sessionService, {
      now: () => new Date("2026-06-01T12:06:00.000Z")
    });

    await expect(service.recoveryRequestStatus(recoveryRequestId)).resolves.toMatchObject({
      recoveryRequest: {
        active: false,
        status: "expired"
      }
    });
  });

  it("rejects unknown recovery request status lookups", async () => {
    const { markRecoveryRequestMissing, sessionService, store } = createFakeStore();
    markRecoveryRequestMissing();
    const service = new DefaultRecoveryCodeService(store, sessionService);

    await expect(service.recoveryRequestStatus(recoveryRequestId)).rejects.toThrow(
      "Recovery request was not found"
    );
  });

  it("cancels active recovery requests", async () => {
    const { recordedEvents, securityEvents, sessionService, store } = createFakeStore();
    const service = new DefaultRecoveryCodeService(store, sessionService, {
      now: () => new Date("2026-06-01T12:02:00.000Z"),
      securityEvents
    });

    await expect(service.cancelRecoveryRequest(recoveryRequestId)).resolves.toEqual({
      ok: true,
      recoveryRequest: {
        id: recoveryRequestId,
        cancelledAt: new Date("2026-06-01T12:02:00.000Z"),
        status: "cancelled"
      }
    });
    expect(recordedEvents).toEqual([
      {
        actorUserId: userId,
        eventType: "recovery_cancelled",
        metadata: {
          cancelledAt: "2026-06-01T12:02:00.000Z",
          recoveryRequestId,
          scope: "recovery_request_cancellation"
        },
        outcome: "success",
        riskLevel: "medium",
        userId
      }
    ]);
  });

  it("rejects expired recovery request cancellation", async () => {
    const { markRecoveryRequestExpired, sessionService, store } = createFakeStore();
    markRecoveryRequestExpired();
    const service = new DefaultRecoveryCodeService(store, sessionService, {
      now: () => new Date("2026-06-01T12:01:00.000Z")
    });

    await expect(service.cancelRecoveryRequest(recoveryRequestId)).rejects.toThrow(
      "Recovery request is expired"
    );
  });

  it("rejects non-pending recovery request cancellation", async () => {
    const { markRecoveryRequestCompleted, sessionService, store } = createFakeStore();
    markRecoveryRequestCompleted();
    const service = new DefaultRecoveryCodeService(store, sessionService);

    await expect(service.cancelRecoveryRequest(recoveryRequestId)).rejects.toThrow(
      "Recovery request is not pending"
    );
  });

  it("completes active recovery requests", async () => {
    const { createdSessions, recordedEvents, securityEvents, sessionService, store } =
      createFakeStore();
    const service = new DefaultRecoveryCodeService(store, sessionService, {
      now: () => new Date("2026-06-01T12:01:00.000Z"),
      recoverySessionTtlSeconds: 300,
      securityEvents
    });

    await expect(service.completeRecoveryRequest(recoveryRequestId)).resolves.toEqual({
      ok: true,
      recoverySession: {
        id: recoverySessionId,
        token: recoverySessionToken,
        expiresAt: new Date("2026-06-01T12:16:00.000Z")
      },
      recoveryRequest: {
        id: recoveryRequestId,
        completedAt: new Date("2026-06-01T12:01:00.000Z"),
        status: "completed"
      }
    });
    expect(createdSessions).toEqual([
      {
        userId,
        deviceLabel: "Recovery session",
        ttlSeconds: 300
      }
    ]);
    expect(recordedEvents).toEqual([
      {
        actorUserId: userId,
        eventType: "recovery_completed",
        metadata: {
          recoveryRequestId,
          recoverySessionId,
          completedAt: "2026-06-01T12:01:00.000Z"
        },
        outcome: "success",
        riskLevel: "medium",
        sessionId: recoverySessionId,
        userId
      },
      {
        eventType: "session_created",
        metadata: {
          deviceLabel: "Recovery session",
          expiresAt: "2026-06-01T12:16:00.000Z",
          ipHashPresent: false,
          reason: "recovery_completed",
          recoveryRequestId,
          userAgent: null
        },
        outcome: "success",
        riskLevel: "medium",
        sessionId: recoverySessionId,
        userId
      }
    ]);
  });

  it("rejects expired recovery request completion", async () => {
    const { markRecoveryRequestExpired, sessionService, store } = createFakeStore();
    markRecoveryRequestExpired();
    const service = new DefaultRecoveryCodeService(store, sessionService, {
      now: () => new Date("2026-06-01T12:01:00.000Z")
    });

    await expect(service.completeRecoveryRequest(recoveryRequestId)).rejects.toThrow(
      "Recovery request is expired"
    );
  });

  it("rejects non-pending recovery request completion", async () => {
    const { markRecoveryRequestCompleted, sessionService, store } = createFakeStore();
    markRecoveryRequestCompleted();
    const service = new DefaultRecoveryCodeService(store, sessionService);

    await expect(service.completeRecoveryRequest(recoveryRequestId)).rejects.toThrow(
      "Recovery request is not pending"
    );
  });
});
