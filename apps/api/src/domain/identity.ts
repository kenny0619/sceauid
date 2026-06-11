export type UserId = string & { readonly __brand: "UserId" };
export type EmailAddressId = string & { readonly __brand: "EmailAddressId" };
export type PasskeyCredentialId = string & { readonly __brand: "PasskeyCredentialId" };
export type SessionId = string & { readonly __brand: "SessionId" };
export type RecoveryCodeId = string & { readonly __brand: "RecoveryCodeId" };
export type RecoveryRequestId = string & { readonly __brand: "RecoveryRequestId" };
export type SecurityEventId = string & { readonly __brand: "SecurityEventId" };

export type UserStatus = "active" | "disabled" | "pending_recovery";
export type RecoveryRequestStatus = "pending" | "verified" | "completed" | "expired" | "cancelled";
export type RiskLevel = "low" | "medium" | "high";
export type SecurityEventOutcome = "success" | "failure" | "pending";

export type SecurityEventType =
  | "signup_started"
  | "email_verified"
  | "passkey_registration_started"
  | "passkey_registered"
  | "passkey_registration_failed"
  | "passkey_removed"
  | "login_started"
  | "login_succeeded"
  | "login_failed"
  | "session_created"
  | "session_revoked"
  | "recovery_codes_enrolled"
  | "recovery_code_redeemed"
  | "recovery_started"
  | "recovery_verified"
  | "recovery_completed"
  | "recovery_cancelled"
  | "recovery_delayed"
  | "rate_limit_triggered"
  | "suspicious_activity_flagged";

export type RequestContext = {
  ipHash?: string;
  userAgent?: string;
  traceId?: string;
};

export type User = {
  id: UserId;
  displayName: string | null;
  status: UserStatus;
  createdAt: Date;
  updatedAt: Date;
};

export type EmailAddress = {
  id: EmailAddressId;
  userId: UserId;
  email: string;
  verified: boolean;
  verifiedAt: Date | null;
  createdAt: Date;
};

export type PasskeyCredential = {
  id: PasskeyCredentialId;
  userId: UserId;
  credentialId: string;
  publicKey: string;
  signCount: number;
  deviceName: string | null;
  lastUsedAt: Date | null;
  createdAt: Date;
  revokedAt: Date | null;
};

export type Session = {
  id: SessionId;
  userId: UserId;
  tokenHash: string;
  deviceLabel: string | null;
  userAgent: string | null;
  ipHash: string | null;
  expiresAt: Date;
  revokedAt: Date | null;
  authenticatedAt: Date;
  createdAt: Date;
};

export type RecoveryCode = {
  id: RecoveryCodeId;
  userId: UserId;
  codeHash: string;
  usedAt: Date | null;
  createdAt: Date;
};

export type RecoveryRequest = {
  id: RecoveryRequestId;
  userId: UserId;
  status: RecoveryRequestStatus;
  riskLevel: RiskLevel;
  expiresAt: Date;
  completedAt: Date | null;
  createdAt: Date;
};

export type SecurityEvent = {
  id: SecurityEventId;
  userId: UserId | null;
  actorUserId: UserId | null;
  sessionId: SessionId | null;
  eventType: SecurityEventType;
  outcome: SecurityEventOutcome;
  riskLevel: RiskLevel;
  metadata: Record<string, unknown>;
  context: RequestContext;
  createdAt: Date;
};

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function isSessionActive(session: Session, now: Date = new Date()): boolean {
  return session.revokedAt === null && session.expiresAt > now;
}

export function isPasskeyActive(credential: PasskeyCredential): boolean {
  return credential.revokedAt === null;
}
