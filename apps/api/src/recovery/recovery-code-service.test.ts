import { describe, expect, it } from "vitest";
import type { RecoveryRequest, RecoveryRequestId, SessionId, UserId } from "../domain/identity.js";
import type {
  CreateRecoveryCodeInput,
  CreateRecoveryRequestInput,
  IdentityStore
} from "../domain/storage.js";
import type { SecurityEventService } from "../security-events/security-event-service.js";
import {
  DefaultRecoveryCodeService,
  hashRecoveryCode,
  normalizeRecoveryCode
} from "./recovery-code-service.js";

const userId = "user-id" as UserId;
const sessionId = "session-id" as SessionId;
const recoveryRequestId = "recovery-request-id" as RecoveryRequestId;

function createFakeStore(options: { unusedRecoveryCodeCount?: number } = {}) {
  const consumedCodes: Array<{ codeHash: string; usedAt: Date; userId: UserId }> = [];
  const createdCodes: CreateRecoveryCodeInput[] = [];
  const createdRecoveryRequests: CreateRecoveryRequestInput[] = [];
  const markedUsed: Array<{ userId: UserId; usedAt: Date }> = [];
  const recordedEvents: Array<Parameters<SecurityEventService["record"]>[0]> = [];
  let consumeRecoveryCodeResult = true;
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
    | "consumeRecoveryCode"
    | "countUnusedRecoveryCodesForUser"
    | "createRecoveryRequest"
    | "createRecoveryCode"
    | "findRecoveryRequestById"
    | "markUnusedRecoveryCodesUsed"
  > = {
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

  return {
    consumedCodes,
    createdCodes,
    createdRecoveryRequests,
    markRecoveryCodeInvalid() {
      consumeRecoveryCodeResult = false;
    },
    markRecoveryRequestMissing() {
      recoveryRequest = null;
    },
    markedUsed,
    recordedEvents,
    securityEvents,
    store
  };
}

describe("DefaultRecoveryCodeService", () => {
  it("normalizes and hashes recovery codes", () => {
    expect(normalizeRecoveryCode("abcd-1234 ef")).toBe("ABCD1234EF");
    expect(hashRecoveryCode("ABCD-1234")).toBe(hashRecoveryCode("abcd 1234"));
  });

  it("rotates unused recovery codes and returns the new codes once", async () => {
    const { createdCodes, markedUsed, recordedEvents, securityEvents, store } = createFakeStore();
    let byte = 0;
    const service = new DefaultRecoveryCodeService(store, {
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
    const { store } = createFakeStore({ unusedRecoveryCodeCount: 3 });
    const service = new DefaultRecoveryCodeService(store);

    await expect(service.status(userId)).resolves.toEqual({
      recoveryCodesConfigured: true,
      unusedRecoveryCodeCount: 3
    });
  });

  it("redeems a recovery code using its normalized hash", async () => {
    const { consumedCodes, createdRecoveryRequests, recordedEvents, securityEvents, store } =
      createFakeStore();
    const service = new DefaultRecoveryCodeService(store, {
      now: () => new Date("2026-06-01T12:00:00.000Z"),
      recoveryRequestTtlSeconds: 300,
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
          redeemedAt: "2026-06-01T12:00:00.000Z"
        },
        outcome: "success",
        riskLevel: "medium",
        userId
      }
    ]);
  });

  it("rejects invalid or used recovery codes", async () => {
    const { markRecoveryCodeInvalid, recordedEvents, securityEvents, store } = createFakeStore();
    markRecoveryCodeInvalid();
    const service = new DefaultRecoveryCodeService(store, { securityEvents });

    await expect(service.redeem({ code: "invalid-code", userId })).rejects.toThrow(
      "Recovery code was invalid or already used"
    );
    expect(recordedEvents).toEqual([]);
  });

  it("returns recovery request status", async () => {
    const { store } = createFakeStore();
    const service = new DefaultRecoveryCodeService(store, {
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
    const { store } = createFakeStore();
    const service = new DefaultRecoveryCodeService(store, {
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
    const { markRecoveryRequestMissing, store } = createFakeStore();
    markRecoveryRequestMissing();
    const service = new DefaultRecoveryCodeService(store);

    await expect(service.recoveryRequestStatus(recoveryRequestId)).rejects.toThrow(
      "Recovery request was not found"
    );
  });
});
