import { createHash, randomBytes } from "node:crypto";
import type { UserId } from "../domain/identity.js";
import type { IdentityStore } from "../domain/storage.js";

export type RecoveryCodeService = {
  enroll(input: EnrollRecoveryCodesInput): Promise<EnrollRecoveryCodesResult>;
  redeem(input: RedeemRecoveryCodeInput): Promise<RedeemRecoveryCodeResult>;
  status(userId: UserId): Promise<RecoveryCodeStatus>;
};

export type EnrollRecoveryCodesInput = {
  userId: UserId;
};

export type EnrollRecoveryCodesResult = {
  codes: string[];
  recoveryCodesConfigured: true;
  unusedRecoveryCodeCount: number;
};

export type RecoveryCodeStatus = {
  recoveryCodesConfigured: boolean;
  unusedRecoveryCodeCount: number;
};

export type RedeemRecoveryCodeInput = {
  code: string;
  userId: UserId;
};

export type RedeemRecoveryCodeResult = {
  ok: true;
};

export type RecoveryCodeServiceOptions = {
  codeCount?: number;
  now?: () => Date;
  randomBytes?: (size: number) => Buffer;
};

const defaultCodeCount = 10;
const codeByteLength = 10;

function formatRecoveryCode(bytes: Buffer): string {
  const hex = bytes.toString("hex").toUpperCase();
  const groups = hex.match(/.{1,5}/g) ?? [];

  return groups.join("-");
}

export function normalizeRecoveryCode(code: string): string {
  return code.replace(/[\s-]/g, "").toUpperCase();
}

export function hashRecoveryCode(code: string): string {
  return createHash("sha256").update(normalizeRecoveryCode(code)).digest("hex");
}

export class DefaultRecoveryCodeService implements RecoveryCodeService {
  private readonly codeCount: number;
  private readonly now: () => Date;
  private readonly randomBytes: (size: number) => Buffer;

  constructor(
    private readonly store: Pick<
      IdentityStore,
      | "consumeRecoveryCode"
      | "countUnusedRecoveryCodesForUser"
      | "createRecoveryCode"
      | "markUnusedRecoveryCodesUsed"
    >,
    options: RecoveryCodeServiceOptions = {}
  ) {
    this.codeCount = options.codeCount ?? defaultCodeCount;
    this.now = options.now ?? (() => new Date());
    this.randomBytes = options.randomBytes ?? randomBytes;
  }

  async enroll(input: EnrollRecoveryCodesInput): Promise<EnrollRecoveryCodesResult> {
    await this.store.markUnusedRecoveryCodesUsed(input.userId, this.now());

    const codes = Array.from({ length: this.codeCount }, () =>
      formatRecoveryCode(this.randomBytes(codeByteLength))
    );

    for (const code of codes) {
      await this.store.createRecoveryCode({
        userId: input.userId,
        codeHash: hashRecoveryCode(code)
      });
    }

    return {
      codes,
      recoveryCodesConfigured: true,
      unusedRecoveryCodeCount: codes.length
    };
  }

  async redeem(input: RedeemRecoveryCodeInput): Promise<RedeemRecoveryCodeResult> {
    const consumed = await this.store.consumeRecoveryCode(
      input.userId,
      hashRecoveryCode(input.code),
      this.now()
    );

    if (!consumed) {
      throw new Error("Recovery code was invalid or already used");
    }

    return { ok: true };
  }

  async status(userId: UserId): Promise<RecoveryCodeStatus> {
    const unusedRecoveryCodeCount = await this.store.countUnusedRecoveryCodesForUser(userId);

    return {
      recoveryCodesConfigured: unusedRecoveryCodeCount > 0,
      unusedRecoveryCodeCount
    };
  }
}
