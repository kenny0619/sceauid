import { randomUUID } from "node:crypto";
import {
  type PublicKeyCredentialRequestOptionsJSON,
  generateAuthenticationOptions
} from "@simplewebauthn/server";
import type { PasskeyCredential, RequestContext, User, UserId } from "../domain/identity.js";
import { isPasskeyActive } from "../domain/identity.js";
import type { ChallengeStore, IdentityStore } from "../domain/storage.js";
import type { SecurityEventService } from "../security-events/security-event-service.js";

export type PasskeyLoginStartConfig = {
  rpId: string;
  origin: string;
};

export type StartPasskeyLoginInput = {
  context?: RequestContext;
  userId?: UserId;
};

export type StartPasskeyLoginResult = {
  loginId: string;
  options: PublicKeyCredentialRequestOptionsJSON;
  expiresAt: Date;
};

export type PasskeyLoginStartService = {
  start(input?: StartPasskeyLoginInput): Promise<StartPasskeyLoginResult>;
};

export type GenerateAuthenticationOptions = typeof generateAuthenticationOptions;

export type PasskeyLoginStartServiceOptions = {
  now?: () => Date;
  ttlSeconds?: number;
  createLoginId?: () => string;
  generateOptions?: GenerateAuthenticationOptions;
  securityEvents?: SecurityEventService;
};

const defaultTtlSeconds = 60 * 5;
const discoverableSubject = "discoverable";

function assertActiveUser(user: User | null): asserts user is User {
  if (!user) {
    throw new Error("User was not found");
  }

  if (user.status !== "active") {
    throw new Error("User cannot start passkey login unless active");
  }
}

function resolveTtlSeconds(ttlSeconds: number | undefined): number {
  if (ttlSeconds === undefined) {
    return defaultTtlSeconds;
  }

  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1) {
    throw new Error("Passkey login TTL must be a positive integer number of seconds");
  }

  return ttlSeconds;
}

function resolveExpiresAt(now: Date, ttlSeconds: number): Date {
  return new Date(now.getTime() + ttlSeconds * 1000);
}

function allowActiveCredentials(credentials: PasskeyCredential[]) {
  return credentials.filter(isPasskeyActive).map((credential) => ({
    id: credential.credentialId
  }));
}

export class DefaultPasskeyLoginStartService implements PasskeyLoginStartService {
  private readonly now: () => Date;
  private readonly ttlSeconds: number;
  private readonly createLoginId: () => string;
  private readonly generateOptions: GenerateAuthenticationOptions;
  private readonly securityEvents: SecurityEventService | undefined;

  constructor(
    private readonly identityStore: Pick<IdentityStore, "findUserById" | "listPasskeysForUser">,
    private readonly challengeStore: ChallengeStore,
    private readonly config: PasskeyLoginStartConfig,
    options: PasskeyLoginStartServiceOptions = {}
  ) {
    this.now = options.now ?? (() => new Date());
    this.ttlSeconds = resolveTtlSeconds(options.ttlSeconds);
    this.createLoginId = options.createLoginId ?? (() => randomUUID());
    this.generateOptions = options.generateOptions ?? generateAuthenticationOptions;
    this.securityEvents = options.securityEvents;
  }

  async start(input: StartPasskeyLoginInput = {}): Promise<StartPasskeyLoginResult> {
    const expiresAt = resolveExpiresAt(this.now(), this.ttlSeconds);
    const loginId = this.createLoginId();
    const allowCredentials = await this.resolveAllowCredentials(input.userId);
    const options = await this.generateOptions({
      rpID: this.config.rpId,
      allowCredentials,
      timeout: this.ttlSeconds * 1000,
      userVerification: "preferred"
    });

    await this.challengeStore.createChallenge({
      id: loginId,
      purpose: "passkey_login",
      subject: input.userId ?? discoverableSubject,
      payload: {
        challenge: options.challenge,
        rpId: this.config.rpId,
        origin: this.config.origin,
        userId: input.userId ?? null
      },
      expiresAt
    });

    await this.recordSecurityEvent({
      userId: input.userId ?? null,
      eventType: "login_started",
      outcome: "pending",
      metadata: {
        loginId,
        mode: input.userId ? "scoped" : "discoverable",
        allowedCredentials: allowCredentials?.length ?? null
      },
      ...(input.context ? { context: input.context } : {})
    });

    return { loginId, options, expiresAt };
  }

  private async recordSecurityEvent(
    input: Parameters<SecurityEventService["record"]>[0]
  ): Promise<void> {
    await this.securityEvents?.record(input).catch(() => undefined);
  }

  private async resolveAllowCredentials(userId: UserId | undefined) {
    if (!userId) {
      return undefined;
    }

    const user = await this.identityStore.findUserById(userId);
    assertActiveUser(user);

    const passkeys = await this.identityStore.listPasskeysForUser(userId);
    const allowCredentials = allowActiveCredentials(passkeys);

    if (allowCredentials.length === 0) {
      throw new Error("User has no active passkeys");
    }

    return allowCredentials;
  }
}
