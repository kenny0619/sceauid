import { describe, expect, it } from "vitest";
import type { UserId } from "../domain/identity.js";
import type { CreateRecoveryCodeInput, IdentityStore } from "../domain/storage.js";
import {
  DefaultRecoveryCodeService,
  hashRecoveryCode,
  normalizeRecoveryCode
} from "./recovery-code-service.js";

const userId = "user-id" as UserId;

function createFakeStore(options: { unusedRecoveryCodeCount?: number } = {}) {
  const consumedCodes: Array<{ codeHash: string; usedAt: Date; userId: UserId }> = [];
  const createdCodes: CreateRecoveryCodeInput[] = [];
  const markedUsed: Array<{ userId: UserId; usedAt: Date }> = [];
  let consumeRecoveryCodeResult = true;

  const store: Pick<
    IdentityStore,
    | "consumeRecoveryCode"
    | "countUnusedRecoveryCodesForUser"
    | "createRecoveryCode"
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
    async markUnusedRecoveryCodesUsed(markUserId, usedAt) {
      markedUsed.push({ userId: markUserId, usedAt });
    }
  };

  return {
    consumedCodes,
    createdCodes,
    markRecoveryCodeInvalid() {
      consumeRecoveryCodeResult = false;
    },
    markedUsed,
    store
  };
}

describe("DefaultRecoveryCodeService", () => {
  it("normalizes and hashes recovery codes", () => {
    expect(normalizeRecoveryCode("abcd-1234 ef")).toBe("ABCD1234EF");
    expect(hashRecoveryCode("ABCD-1234")).toBe(hashRecoveryCode("abcd 1234"));
  });

  it("rotates unused recovery codes and returns the new codes once", async () => {
    const { createdCodes, markedUsed, store } = createFakeStore();
    let byte = 0;
    const service = new DefaultRecoveryCodeService(store, {
      codeCount: 2,
      now: () => new Date("2026-06-01T12:00:00.000Z"),
      randomBytes(size) {
        const buffer = Buffer.alloc(size, byte);
        byte += 1;
        return buffer;
      }
    });

    const result = await service.enroll({ userId });

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
    const { consumedCodes, store } = createFakeStore();
    const service = new DefaultRecoveryCodeService(store, {
      now: () => new Date("2026-06-01T12:00:00.000Z")
    });

    await expect(service.redeem({ code: "abcd-1234 ef", userId })).resolves.toEqual({ ok: true });

    expect(consumedCodes).toEqual([
      {
        codeHash: hashRecoveryCode("ABCD1234EF"),
        usedAt: new Date("2026-06-01T12:00:00.000Z"),
        userId
      }
    ]);
  });

  it("rejects invalid or used recovery codes", async () => {
    const { markRecoveryCodeInvalid, store } = createFakeStore();
    markRecoveryCodeInvalid();
    const service = new DefaultRecoveryCodeService(store);

    await expect(service.redeem({ code: "invalid-code", userId })).rejects.toThrow(
      "Recovery code was invalid or already used"
    );
  });
});
