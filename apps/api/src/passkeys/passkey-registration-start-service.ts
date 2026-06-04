import { randomUUID } from "node:crypto";
import {
  type PublicKeyCredentialCreationOptionsJSON,
  type Uint8Array_,
  generateRegistrationOptions
} from "@simplewebauthn/server";
import type { PasskeyCredential, User, UserId } from "../domain/identity.js";
import { isPasskeyActive } from "../domain/identity.js";
import type { ChallengeStore, IdentityStore } from "../domain/storage.js";
import type { SecurityEventService } from "../security-events/security-event-service.js";

export type PasskeyRegistrationStartConfig = {
  rpName: string;
  rpId: string;
  origin: string;
};

export type StartPasskeyRegistrationInput = {
  userId: UserId;
  userName: string;
  userDisplayName?: string | null;
};

export type StartPasskeyRegistrationResult = {
  registrationId: string;
  options: PublicKeyCredentialCreationOptionsJSON;
  expiresAt: Date;
};

export type PasskeyRegistrationStartService = {
  start(input: StartPasskeyRegistrationInput): Promise<StartPasskeyRegistrationResult>;
};

export type GenerateRegistrationOptions = typeof generateRegistrationOptions;

export type PasskeyRegistrationStartServiceOptions = {
  now?: () => Date;
  ttlSeconds?: number;
  createRegistrationId?: () => string;
  generateOptions?: GenerateRegistrationOptions;
  securityEvents?: SecurityEventService;
};

const defaultTtlSeconds = 60 * 5;

function assertActiveUser(user: User | null): asserts user is User {
  if (!user) {
    throw new Error("User was not found");
  }

  if (user.status !== "active") {
    throw new Error("User cannot register passkeys unless active");
  }
}

function resolveTtlSeconds(ttlSeconds: number | undefined): number {
  if (ttlSeconds === undefined) {
    return defaultTtlSeconds;
  }

  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1) {
    throw new Error("Passkey registration TTL must be a positive integer number of seconds");
  }

  return ttlSeconds;
}

function resolveExpiresAt(now: Date, ttlSeconds: number): Date {
  return new Date(now.getTime() + ttlSeconds * 1000);
}

function userIdToBytes(userId: UserId): Uint8Array_ {
  return new TextEncoder().encode(userId) as Uint8Array_;
}

function excludeActiveCredentials(credentials: PasskeyCredential[]) {
  return credentials.filter(isPasskeyActive).map((credential) => ({
    id: credential.credentialId
  }));
}

export class DefaultPasskeyRegistrationStartService implements PasskeyRegistrationStartService {
  private readonly now: () => Date;
  private readonly ttlSeconds: number;
  private readonly createRegistrationId: () => string;
  private readonly generateOptions: GenerateRegistrationOptions;
  private readonly securityEvents: SecurityEventService | undefined;

  constructor(
    private readonly identityStore: Pick<IdentityStore, "findUserById" | "listPasskeysForUser">,
    private readonly challengeStore: ChallengeStore,
    private readonly config: PasskeyRegistrationStartConfig,
    options: PasskeyRegistrationStartServiceOptions = {}
  ) {
    this.now = options.now ?? (() => new Date());
    this.ttlSeconds = resolveTtlSeconds(options.ttlSeconds);
    this.createRegistrationId = options.createRegistrationId ?? (() => randomUUID());
    this.generateOptions = options.generateOptions ?? generateRegistrationOptions;
    this.securityEvents = options.securityEvents;
  }

  async start(input: StartPasskeyRegistrationInput): Promise<StartPasskeyRegistrationResult> {
    const user = await this.identityStore.findUserById(input.userId);
    assertActiveUser(user);

    const passkeys = await this.identityStore.listPasskeysForUser(input.userId);
    const expiresAt = resolveExpiresAt(this.now(), this.ttlSeconds);
    const registrationId = this.createRegistrationId();
    const options = await this.generateOptions({
      rpName: this.config.rpName,
      rpID: this.config.rpId,
      userName: input.userName,
      userID: userIdToBytes(input.userId),
      userDisplayName: input.userDisplayName ?? user.displayName ?? input.userName,
      timeout: this.ttlSeconds * 1000,
      attestationType: "none",
      excludeCredentials: excludeActiveCredentials(passkeys),
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred"
      }
    });

    await this.challengeStore.createChallenge({
      id: registrationId,
      purpose: "passkey_registration",
      subject: input.userId,
      payload: {
        challenge: options.challenge,
        userHandle: options.user.id,
        rpId: this.config.rpId,
        origin: this.config.origin
      },
      expiresAt
    });

    await this.recordSecurityEvent({
      userId: input.userId,
      eventType: "passkey_registration_started",
      outcome: "pending",
      metadata: {
        registrationId,
        existingActivePasskeys: excludeActiveCredentials(passkeys).length
      }
    });

    return { registrationId, options, expiresAt };
  }

  private async recordSecurityEvent(
    input: Parameters<SecurityEventService["record"]>[0]
  ): Promise<void> {
    await this.securityEvents?.record(input).catch(() => undefined);
  }
}
