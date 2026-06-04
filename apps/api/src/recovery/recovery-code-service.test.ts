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
  const createdCodes: CreateRecoveryCodeInput[] = [];
  const markedUsed: Array<{ userId: UserId; usedAt: Date }> = [];

  const store: Pick<
    IdentityStore,
    "countUnusedRecoveryCodesForUser" | "createRecoveryCode" | "markUnusedRecoveryCodesUsed"
  > = {
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

  return { createdCodes, markedUsed, store };
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
});
