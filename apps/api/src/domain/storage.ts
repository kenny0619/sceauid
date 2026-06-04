import type {
  EmailAddress,
  PasskeyCredential,
  RecoveryCode,
  RecoveryRequest,
  SecurityEvent,
  SecurityEventType,
  Session,
  SessionId,
  User,
  UserId
} from "./identity.js";

export type CreateUserInput = {
  displayName?: string | null;
};

export type CreateEmailAddressInput = {
  userId: UserId;
  email: string;
  verified?: boolean;
};

export type CreatePasskeyCredentialInput = {
  userId: UserId;
  credentialId: string;
  publicKey: string;
  signCount: number;
  deviceName?: string | null;
};

export type UpdatePasskeyUsageInput = {
  credentialId: string;
  signCount: number;
  usedAt: Date;
};

export type CreateSessionInput = {
  userId: UserId;
  tokenHash: string;
  deviceLabel?: string | null;
  userAgent?: string | null;
  ipHash?: string | null;
  expiresAt: Date;
};

export type CreateRecoveryCodeInput = {
  userId: UserId;
  codeHash: string;
};

export type CreateRecoveryRequestInput = {
  userId: UserId;
  riskLevel: RecoveryRequest["riskLevel"];
  expiresAt: Date;
};

export type CreateSecurityEventInput = Omit<SecurityEvent, "id" | "createdAt">;

export type IdentityStore = {
  createUser(input: CreateUserInput): Promise<User>;
  findUserById(userId: UserId): Promise<User | null>;

  createEmailAddress(input: CreateEmailAddressInput): Promise<EmailAddress>;
  findUserByEmail(email: string): Promise<User | null>;
  markEmailVerified(email: string, verifiedAt: Date): Promise<void>;

  createPasskeyCredential(input: CreatePasskeyCredentialInput): Promise<PasskeyCredential>;
  findPasskeyByCredentialId(credentialId: string): Promise<PasskeyCredential | null>;
  listPasskeysForUser(userId: UserId): Promise<PasskeyCredential[]>;
  updatePasskeyUsage(input: UpdatePasskeyUsageInput): Promise<void>;
  revokePasskeyCredential(credentialId: string, revokedAt: Date): Promise<void>;

  createSession(input: CreateSessionInput): Promise<Session>;
  findSessionByTokenHash(tokenHash: string): Promise<Session | null>;
  listSessionsForUser(userId: UserId): Promise<Session[]>;
  revokeSession(sessionId: SessionId, revokedAt: Date): Promise<void>;
  revokeUserSessions(userId: UserId, revokedAt: Date): Promise<void>;

  createRecoveryCode(input: CreateRecoveryCodeInput): Promise<RecoveryCode>;
  findUnusedRecoveryCode(userId: UserId, codeHash: string): Promise<RecoveryCode | null>;
  markRecoveryCodeUsed(userId: UserId, codeHash: string, usedAt: Date): Promise<void>;

  createRecoveryRequest(input: CreateRecoveryRequestInput): Promise<RecoveryRequest>;
  findActiveRecoveryRequest(userId: UserId, now: Date): Promise<RecoveryRequest | null>;
  completeRecoveryRequest(userId: UserId, completedAt: Date): Promise<void>;

  createSecurityEvent(input: CreateSecurityEventInput): Promise<SecurityEvent>;
  listSecurityEventsForUser(filter: SecurityEventFilter): Promise<SecurityEvent[]>;
};

export type ChallengePurpose = "passkey_registration" | "passkey_login" | "email_recovery";

export type ChallengeRecord = {
  id: string;
  purpose: ChallengePurpose;
  subject: string;
  payload: Record<string, unknown>;
  expiresAt: Date;
};

export type ChallengeStore = {
  createChallenge(record: ChallengeRecord): Promise<void>;
  consumeChallenge(id: string, purpose: ChallengePurpose): Promise<ChallengeRecord | null>;
};

export type RateLimitResult = {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAt: Date;
};

export type RiskStore = {
  checkRateLimit(key: string, limit: number, windowSeconds: number): Promise<RateLimitResult>;
};

export type SecurityEventFilter = {
  userId?: UserId;
  eventTypes?: SecurityEventType[];
  limit: number;
};
