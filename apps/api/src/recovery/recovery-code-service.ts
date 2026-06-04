import { createHash, randomBytes } from "node:crypto";
import type {
  RecoveryRequest,
  RecoveryRequestId,
  RecoveryRequestStatus,
  SessionId,
  UserId
} from "../domain/identity.js";
import type { IdentityStore } from "../domain/storage.js";
import type { SecurityEventService } from "../security-events/security-event-service.js";

export type RecoveryCodeService = {
  enroll(input: EnrollRecoveryCodesInput): Promise<EnrollRecoveryCodesResult>;
  redeem(input: RedeemRecoveryCodeInput): Promise<RedeemRecoveryCodeResult>;
  recoveryRequestStatus(recoveryRequestId: RecoveryRequestId): Promise<RecoveryRequestStatusResult>;
  status(userId: UserId): Promise<RecoveryCodeStatus>;
};

export type EnrollRecoveryCodesInput = {
  actorSessionId?: SessionId | null;
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
  recoveryRequest: {
    id: RecoveryRequestId;
    expiresAt: Date;
    riskLevel: "medium";
  };
};

export type RecoveryRequestStatusResult = {
  recoveryRequest: {
    id: RecoveryRequestId;
    active: boolean;
    expiresAt: Date;
    riskLevel: RecoveryRequest["riskLevel"];
    status: RecoveryRequestStatus;
  };
};

export type RecoveryCodeServiceOptions = {
  codeCount?: number;
  now?: () => Date;
  randomBytes?: (size: number) => Buffer;
  recoveryRequestTtlSeconds?: number;
  securityEvents?: SecurityEventService;
};

const defaultCodeCount = 10;
const defaultRecoveryRequestTtlSeconds = 60 * 15;
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
  private readonly recoveryRequestTtlSeconds: number;
  private readonly securityEvents: SecurityEventService | undefined;

  constructor(
    private readonly store: Pick<
      IdentityStore,
      | "consumeRecoveryCode"
      | "countUnusedRecoveryCodesForUser"
      | "createRecoveryRequest"
      | "createRecoveryCode"
      | "findRecoveryRequestById"
      | "markUnusedRecoveryCodesUsed"
    >,
    options: RecoveryCodeServiceOptions = {}
  ) {
    this.codeCount = options.codeCount ?? defaultCodeCount;
    this.now = options.now ?? (() => new Date());
    this.randomBytes = options.randomBytes ?? randomBytes;
    this.recoveryRequestTtlSeconds =
      options.recoveryRequestTtlSeconds ?? defaultRecoveryRequestTtlSeconds;
    this.securityEvents = options.securityEvents;
  }

  async enroll(input: EnrollRecoveryCodesInput): Promise<EnrollRecoveryCodesResult> {
    const enrolledAt = this.now();
    await this.store.markUnusedRecoveryCodesUsed(input.userId, enrolledAt);

    const codes = Array.from({ length: this.codeCount }, () =>
      formatRecoveryCode(this.randomBytes(codeByteLength))
    );

    for (const code of codes) {
      await this.store.createRecoveryCode({
        userId: input.userId,
        codeHash: hashRecoveryCode(code)
      });
    }

    await this.recordSecurityEvent({
      userId: input.userId,
      actorUserId: input.userId,
      sessionId: input.actorSessionId ?? null,
      eventType: "recovery_codes_enrolled",
      outcome: "success",
      metadata: {
        codeCount: codes.length,
        enrolledAt: enrolledAt.toISOString()
      }
    });

    return {
      codes,
      recoveryCodesConfigured: true,
      unusedRecoveryCodeCount: codes.length
    };
  }

  async redeem(input: RedeemRecoveryCodeInput): Promise<RedeemRecoveryCodeResult> {
    const redeemedAt = this.now();
    const consumed = await this.store.consumeRecoveryCode(
      input.userId,
      hashRecoveryCode(input.code),
      redeemedAt
    );

    if (!consumed) {
      throw new Error("Recovery code was invalid or already used");
    }

    const recoveryRequest = await this.store.createRecoveryRequest({
      userId: input.userId,
      riskLevel: "medium",
      expiresAt: new Date(redeemedAt.getTime() + this.recoveryRequestTtlSeconds * 1000)
    });

    await this.recordSecurityEvent({
      userId: input.userId,
      actorUserId: input.userId,
      eventType: "recovery_code_redeemed",
      outcome: "success",
      riskLevel: "medium",
      metadata: {
        recoveryRequestId: recoveryRequest.id,
        redeemedAt: redeemedAt.toISOString()
      }
    });

    return {
      ok: true,
      recoveryRequest: {
        id: recoveryRequest.id,
        expiresAt: recoveryRequest.expiresAt,
        riskLevel: "medium"
      }
    };
  }

  async recoveryRequestStatus(
    recoveryRequestId: RecoveryRequestId
  ): Promise<RecoveryRequestStatusResult> {
    const recoveryRequest = await this.store.findRecoveryRequestById(recoveryRequestId);

    if (!recoveryRequest) {
      throw new Error("Recovery request was not found");
    }

    const status =
      recoveryRequest.status === "pending" && recoveryRequest.expiresAt <= this.now()
        ? "expired"
        : recoveryRequest.status;

    return {
      recoveryRequest: {
        id: recoveryRequest.id,
        active: status === "pending",
        expiresAt: recoveryRequest.expiresAt,
        riskLevel: recoveryRequest.riskLevel,
        status
      }
    };
  }

  async status(userId: UserId): Promise<RecoveryCodeStatus> {
    const unusedRecoveryCodeCount = await this.store.countUnusedRecoveryCodesForUser(userId);

    return {
      recoveryCodesConfigured: unusedRecoveryCodeCount > 0,
      unusedRecoveryCodeCount
    };
  }

  private async recordSecurityEvent(
    input: Parameters<SecurityEventService["record"]>[0]
  ): Promise<void> {
    await this.securityEvents?.record(input).catch(() => undefined);
  }
}
