import { createHash, randomBytes } from "node:crypto";
import type {
  RecoveryRequest,
  RecoveryRequestId,
  RecoveryRequestStatus,
  SessionId,
  UserId
} from "../domain/identity.js";
import type { IdentityStore } from "../domain/storage.js";
import type { RiskStore } from "../domain/storage.js";
import type { SecurityEventService } from "../security-events/security-event-service.js";
import type { CreatedSession, SessionService } from "../sessions/session-service.js";

export type RecoveryCodeService = {
  cancelRecoveryRequest(recoveryRequestId: RecoveryRequestId): Promise<CancelRecoveryRequestResult>;
  completeRecoveryRequest(
    recoveryRequestId: RecoveryRequestId
  ): Promise<CompleteRecoveryRequestResult>;
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

export type CompleteRecoveryRequestResult = {
  ok: true;
  recoverySession: {
    id: SessionId;
    token: string;
    expiresAt: Date;
  };
  recoveryRequest: {
    id: RecoveryRequestId;
    completedAt: Date;
    status: "completed";
  };
};

export type CancelRecoveryRequestResult = {
  ok: true;
  recoveryRequest: {
    id: RecoveryRequestId;
    cancelledAt: Date;
    status: "cancelled";
  };
};

export type RecoveryCodeServiceOptions = {
  codeCount?: number;
  now?: () => Date;
  randomBytes?: (size: number) => Buffer;
  redemptionRateLimit?: {
    limit: number;
    windowSeconds: number;
  };
  riskStore?: RiskStore;
  recoveryRequestTtlSeconds?: number;
  recoverySessionTtlSeconds?: number;
  securityEvents?: SecurityEventService;
};

const defaultCodeCount = 10;
const defaultRedemptionRateLimit = {
  limit: 5,
  windowSeconds: 60 * 15
};
const defaultRecoveryRequestTtlSeconds = 60 * 15;
const defaultRecoverySessionTtlSeconds = 60 * 15;
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
  private readonly redemptionRateLimit: { limit: number; windowSeconds: number };
  private readonly recoveryRequestTtlSeconds: number;
  private readonly recoverySessionTtlSeconds: number;
  private readonly riskStore: RiskStore | undefined;
  private readonly securityEvents: SecurityEventService | undefined;

  constructor(
    private readonly store: Pick<
      IdentityStore,
      | "cancelActiveRecoveryRequest"
      | "completeActiveRecoveryRequest"
      | "consumeRecoveryCode"
      | "countUnusedRecoveryCodesForUser"
      | "createRecoveryRequest"
      | "createRecoveryCode"
      | "findRecoveryRequestById"
      | "markUnusedRecoveryCodesUsed"
    >,
    private readonly sessionService: Pick<SessionService, "create">,
    options: RecoveryCodeServiceOptions = {}
  ) {
    this.codeCount = options.codeCount ?? defaultCodeCount;
    this.now = options.now ?? (() => new Date());
    this.randomBytes = options.randomBytes ?? randomBytes;
    this.redemptionRateLimit = options.redemptionRateLimit ?? defaultRedemptionRateLimit;
    this.recoveryRequestTtlSeconds =
      options.recoveryRequestTtlSeconds ?? defaultRecoveryRequestTtlSeconds;
    this.recoverySessionTtlSeconds =
      options.recoverySessionTtlSeconds ?? defaultRecoverySessionTtlSeconds;
    this.riskStore = options.riskStore;
    this.securityEvents = options.securityEvents;
  }

  async cancelRecoveryRequest(
    recoveryRequestId: RecoveryRequestId
  ): Promise<CancelRecoveryRequestResult> {
    const cancelledAt = this.now();
    const cancelled = await this.store.cancelActiveRecoveryRequest(recoveryRequestId, cancelledAt);

    if (!cancelled) {
      const existingRequest = await this.store.findRecoveryRequestById(recoveryRequestId);

      if (!existingRequest) {
        throw new Error("Recovery request was not found");
      }

      if (existingRequest.status !== "pending") {
        throw new Error("Recovery request is not pending");
      }

      if (existingRequest.expiresAt <= cancelledAt) {
        throw new Error("Recovery request is expired");
      }

      throw new Error("Recovery request could not be cancelled");
    }

    await this.recordSecurityEvent({
      userId: cancelled.userId,
      actorUserId: cancelled.userId,
      eventType: "recovery_cancelled",
      outcome: "success",
      riskLevel: cancelled.riskLevel,
      metadata: {
        cancelledAt: cancelledAt.toISOString(),
        recoveryRequestId: cancelled.id,
        scope: "recovery_request_cancellation"
      }
    });

    return {
      ok: true,
      recoveryRequest: {
        id: cancelled.id,
        cancelledAt,
        status: "cancelled"
      }
    };
  }

  async completeRecoveryRequest(
    recoveryRequestId: RecoveryRequestId
  ): Promise<CompleteRecoveryRequestResult> {
    const completedAt = this.now();
    const completed = await this.store.completeActiveRecoveryRequest(
      recoveryRequestId,
      completedAt
    );

    if (!completed) {
      const existingRequest = await this.store.findRecoveryRequestById(recoveryRequestId);

      if (!existingRequest) {
        throw new Error("Recovery request was not found");
      }

      if (existingRequest.status !== "pending") {
        throw new Error("Recovery request is not pending");
      }

      if (existingRequest.expiresAt <= completedAt) {
        throw new Error("Recovery request is expired");
      }

      throw new Error("Recovery request could not be completed");
    }

    const recoverySession = await this.sessionService.create({
      userId: completed.userId,
      deviceLabel: "Recovery session",
      ttlSeconds: this.recoverySessionTtlSeconds
    });

    await this.recordSecurityEvent({
      userId: completed.userId,
      actorUserId: completed.userId,
      sessionId: recoverySession.session.id,
      eventType: "recovery_completed",
      outcome: "success",
      riskLevel: completed.riskLevel,
      metadata: {
        recoveryRequestId: completed.id,
        recoverySessionId: recoverySession.session.id,
        completedAt: completedAt.toISOString()
      }
    });
    await this.recordSessionCreatedEvent(completed, recoverySession);

    return {
      ok: true,
      recoverySession: {
        id: recoverySession.session.id,
        token: recoverySession.token,
        expiresAt: recoverySession.session.expiresAt
      },
      recoveryRequest: {
        id: completed.id,
        completedAt,
        status: "completed"
      }
    };
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
    const rateLimit = await this.riskStore?.checkRateLimit(
      `recovery-code-redemption:user:${input.userId}`,
      this.redemptionRateLimit.limit,
      this.redemptionRateLimit.windowSeconds
    );

    if (rateLimit && !rateLimit.allowed) {
      await this.recordSecurityEvent({
        userId: input.userId,
        actorUserId: input.userId,
        eventType: "rate_limit_triggered",
        outcome: "failure",
        riskLevel: "medium",
        metadata: {
          attemptedAt: redeemedAt.toISOString(),
          limit: rateLimit.limit,
          remaining: rateLimit.remaining,
          resetAt: rateLimit.resetAt.toISOString(),
          scope: "recovery_code_redemption",
          windowSeconds: this.redemptionRateLimit.windowSeconds
        }
      });

      throw new Error("Recovery code redemption rate limit exceeded");
    }

    const consumed = await this.store.consumeRecoveryCode(
      input.userId,
      hashRecoveryCode(input.code),
      redeemedAt
    );

    if (!consumed) {
      await this.recordSecurityEvent({
        userId: input.userId,
        actorUserId: input.userId,
        eventType: "recovery_code_redeemed",
        outcome: "failure",
        riskLevel: "medium",
        metadata: {
          attemptedAt: redeemedAt.toISOString(),
          reason: "invalid_or_used",
          scope: "recovery_code_redemption"
        }
      });

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
        redeemedAt: redeemedAt.toISOString(),
        scope: "recovery_code_redemption"
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

  private async recordSessionCreatedEvent(
    recoveryRequest: RecoveryRequest,
    recoverySession: CreatedSession
  ): Promise<void> {
    await this.recordSecurityEvent({
      userId: recoveryRequest.userId,
      sessionId: recoverySession.session.id,
      eventType: "session_created",
      outcome: "success",
      riskLevel: recoveryRequest.riskLevel,
      metadata: {
        deviceLabel: recoverySession.session.deviceLabel,
        expiresAt: recoverySession.session.expiresAt.toISOString(),
        ipHashPresent: recoverySession.session.ipHash !== null,
        recoveryRequestId: recoveryRequest.id,
        reason: "recovery_completed",
        userAgent: recoverySession.session.userAgent
      }
    });
  }
}
