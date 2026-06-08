import {
  type RegistrationResponseJSON,
  type VerifiedRegistrationResponse,
  verifyRegistrationResponse
} from "@simplewebauthn/server";
import type { PasskeyCredential, SessionId, User, UserId } from "../domain/identity.js";
import type { ChallengeRecord, ChallengeStore, IdentityStore } from "../domain/storage.js";
import type { SecurityEventService } from "../security-events/security-event-service.js";
import type { SessionService } from "../sessions/session-service.js";

export type PasskeyRegistrationFinishConfig = {
  rpId: string;
  origin: string;
};

export type FinishPasskeyRegistrationInput = {
  registrationId: string;
  credential: RegistrationResponseJSON;
  deviceName?: string | null;
};

export type FinishPasskeyRegistrationResult = {
  userId: UserId;
  credential: PasskeyCredential;
};

export type PasskeyRegistrationFinishService = {
  finish(input: FinishPasskeyRegistrationInput): Promise<FinishPasskeyRegistrationResult>;
};

export type VerifyRegistrationResponse = typeof verifyRegistrationResponse;

export type PasskeyRegistrationFinishServiceOptions = {
  verifyRegistration?: VerifyRegistrationResponse;
  securityEvents?: SecurityEventService;
  sessionService?: Pick<SessionService, "revoke">;
};

type RegistrationChallengePayload = {
  challenge: string;
  registrationContext: Record<string, unknown>;
  userHandle: string;
  rpId: string;
  origin: string;
};

function assertActiveUser(user: User | null): asserts user is User {
  if (!user) {
    throw new Error("User was not found");
  }

  if (user.status !== "active") {
    throw new Error("User cannot register passkeys unless active");
  }
}

function resolveChallengePayload(record: ChallengeRecord): RegistrationChallengePayload {
  const { payload } = record;

  if (
    typeof payload.challenge !== "string" ||
    typeof payload.userHandle !== "string" ||
    typeof payload.rpId !== "string" ||
    typeof payload.origin !== "string"
  ) {
    throw new Error("Passkey registration challenge payload is invalid");
  }

  return {
    challenge: payload.challenge,
    registrationContext:
      payload.registrationContext &&
      typeof payload.registrationContext === "object" &&
      !Array.isArray(payload.registrationContext)
        ? (payload.registrationContext as Record<string, unknown>)
        : { flow: "standard" },
    userHandle: payload.userHandle,
    rpId: payload.rpId,
    origin: payload.origin
  };
}

function assertVerified(
  verification: VerifiedRegistrationResponse
): asserts verification is Extract<VerifiedRegistrationResponse, { verified: true }> {
  if (!verification.verified) {
    throw new Error("Passkey registration verification failed");
  }
}

function encodePublicKey(publicKey: Uint8Array): string {
  return Buffer.from(publicKey).toString("base64url");
}

export class DefaultPasskeyRegistrationFinishService implements PasskeyRegistrationFinishService {
  private readonly verifyRegistration: VerifyRegistrationResponse;
  private readonly securityEvents: SecurityEventService | undefined;
  private readonly sessionService: Pick<SessionService, "revoke"> | undefined;

  constructor(
    private readonly identityStore: Pick<
      IdentityStore,
      "createPasskeyCredential" | "findPasskeyByCredentialId" | "findUserById"
    >,
    private readonly challengeStore: ChallengeStore,
    private readonly config: PasskeyRegistrationFinishConfig,
    options: PasskeyRegistrationFinishServiceOptions = {}
  ) {
    this.verifyRegistration = options.verifyRegistration ?? verifyRegistrationResponse;
    this.securityEvents = options.securityEvents;
    this.sessionService = options.sessionService;
  }

  async finish(input: FinishPasskeyRegistrationInput): Promise<FinishPasskeyRegistrationResult> {
    let auditUserId: UserId | null = null;
    let challenge: ChallengeRecord | null = null;

    try {
      challenge = await this.challengeStore.consumeChallenge(
        input.registrationId,
        "passkey_registration"
      );

      if (!challenge) {
        throw new Error("Passkey registration challenge was not found");
      }

      const userId = challenge.subject as UserId;
      auditUserId = userId;
      const user = await this.identityStore.findUserById(userId);
      assertActiveUser(user);

      const payload = resolveChallengePayload(challenge);
      const verification = await this.verifyRegistration({
        response: input.credential,
        expectedChallenge: payload.challenge,
        expectedOrigin: payload.origin,
        expectedRPID: payload.rpId,
        requireUserVerification: true
      });
      assertVerified(verification);

      if (payload.rpId !== this.config.rpId || payload.origin !== this.config.origin) {
        throw new Error("Passkey registration challenge does not match relying party config");
      }

      const credentialId = verification.registrationInfo.credential.id;
      const existingCredential = await this.identityStore.findPasskeyByCredentialId(credentialId);

      if (existingCredential) {
        throw new Error("Passkey credential already exists");
      }

      const credential = await this.identityStore.createPasskeyCredential({
        userId,
        credentialId,
        publicKey: encodePublicKey(verification.registrationInfo.credential.publicKey),
        signCount: verification.registrationInfo.credential.counter,
        deviceName: input.deviceName ?? null
      });
      const recoverySessionId = resolveRecoverySessionId(payload.registrationContext);

      if (recoverySessionId) {
        await this.sessionService?.revoke(recoverySessionId);
        await this.recordSecurityEvent({
          userId,
          actorUserId: userId,
          sessionId: recoverySessionId,
          eventType: "session_revoked",
          outcome: "success",
          metadata: {
            credentialId,
            reason: "recovery_passkey_registered",
            registrationId: input.registrationId,
            registrationContext: payload.registrationContext
          }
        });
      }

      await this.recordSecurityEvent({
        userId,
        eventType: "passkey_registered",
        outcome: "success",
        metadata: {
          credentialId,
          deviceName: input.deviceName ?? null,
          ...(recoverySessionId ? { recoverySessionFinalized: true } : {}),
          registrationContext: payload.registrationContext,
          registrationId: input.registrationId
        }
      });

      return { userId, credential };
    } catch (error) {
      await this.recordSecurityEvent({
        userId: auditUserId,
        eventType: "passkey_registration_failed",
        outcome: "failure",
        riskLevel: "medium",
        metadata: {
          ...(challenge ? { registrationContext: resolveRegistrationContext(challenge) } : {}),
          registrationId: input.registrationId,
          reason: error instanceof Error ? error.message : "unknown"
        }
      });

      throw error;
    }
  }

  private async recordSecurityEvent(
    input: Parameters<SecurityEventService["record"]>[0]
  ): Promise<void> {
    await this.securityEvents?.record(input).catch(() => undefined);
  }
}

function resolveRegistrationContext(record: ChallengeRecord): Record<string, unknown> {
  const { registrationContext } = record.payload;

  if (
    registrationContext &&
    typeof registrationContext === "object" &&
    !Array.isArray(registrationContext)
  ) {
    return registrationContext as Record<string, unknown>;
  }

  return { flow: "standard" };
}

function resolveRecoverySessionId(registrationContext: Record<string, unknown>): SessionId | null {
  if (
    registrationContext.flow === "recovery" &&
    typeof registrationContext.recoverySessionId === "string" &&
    registrationContext.recoverySessionId.length > 0
  ) {
    return registrationContext.recoverySessionId as SessionId;
  }

  return null;
}
