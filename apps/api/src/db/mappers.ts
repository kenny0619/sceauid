import type {
  EmailAddress,
  EmailAddressId,
  PasskeyCredential,
  PasskeyCredentialId,
  RecoveryCode,
  RecoveryCodeId,
  RecoveryRequest,
  RecoveryRequestId,
  RequestContext,
  SecurityEvent,
  SecurityEventId,
  Session,
  SessionId,
  User,
  UserId
} from "../domain/identity.js";
import type {
  emailAddresses,
  passkeyCredentials,
  recoveryCodes,
  recoveryRequests,
  securityEvents,
  sessions,
  users
} from "./schema.js";

type UserRow = typeof users.$inferSelect;
type EmailAddressRow = typeof emailAddresses.$inferSelect;
type PasskeyCredentialRow = typeof passkeyCredentials.$inferSelect;
type SessionRow = typeof sessions.$inferSelect;
type RecoveryCodeRow = typeof recoveryCodes.$inferSelect;
type RecoveryRequestRow = typeof recoveryRequests.$inferSelect;
type SecurityEventRow = typeof securityEvents.$inferSelect;

function toRecord(value: unknown): Record<string, unknown> {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }

  return {};
}

export function mapUser(row: UserRow): User {
  return {
    id: row.id as UserId,
    displayName: row.displayName,
    status: row.status,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt
  };
}

export function mapEmailAddress(row: EmailAddressRow): EmailAddress {
  return {
    id: row.id as EmailAddressId,
    userId: row.userId as UserId,
    email: row.email,
    verified: row.verified,
    verifiedAt: row.verifiedAt,
    createdAt: row.createdAt
  };
}

export function mapPasskeyCredential(row: PasskeyCredentialRow): PasskeyCredential {
  return {
    id: row.id as PasskeyCredentialId,
    userId: row.userId as UserId,
    credentialId: row.credentialId,
    publicKey: row.publicKey,
    signCount: row.signCount,
    deviceName: row.deviceName,
    lastUsedAt: row.lastUsedAt,
    createdAt: row.createdAt,
    revokedAt: row.revokedAt
  };
}

export function mapSession(row: SessionRow): Session {
  return {
    id: row.id as SessionId,
    userId: row.userId as UserId,
    tokenHash: row.tokenHash,
    deviceLabel: row.deviceLabel,
    userAgent: row.userAgent,
    ipHash: row.ipHash,
    expiresAt: row.expiresAt,
    revokedAt: row.revokedAt,
    authenticatedAt: row.authenticatedAt,
    createdAt: row.createdAt
  };
}

export function mapRecoveryCode(row: RecoveryCodeRow): RecoveryCode {
  return {
    id: row.id as RecoveryCodeId,
    userId: row.userId as UserId,
    codeHash: row.codeHash,
    usedAt: row.usedAt,
    createdAt: row.createdAt
  };
}

export function mapRecoveryRequest(row: RecoveryRequestRow): RecoveryRequest {
  return {
    id: row.id as RecoveryRequestId,
    userId: row.userId as UserId,
    status: row.status,
    riskLevel: row.riskLevel,
    expiresAt: row.expiresAt,
    completedAt: row.completedAt,
    createdAt: row.createdAt
  };
}

export function mapSecurityEvent(row: SecurityEventRow): SecurityEvent {
  return {
    id: row.id as SecurityEventId,
    userId: row.userId as UserId | null,
    actorUserId: row.actorUserId as UserId | null,
    sessionId: row.sessionId as SessionId | null,
    eventType: row.eventType,
    outcome: row.outcome,
    riskLevel: row.riskLevel,
    metadata: toRecord(row.metadata),
    context: toRecord(row.context) as RequestContext,
    createdAt: row.createdAt
  };
}
