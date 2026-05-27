import { and, desc, eq, gt, isNull } from "drizzle-orm";
import { type SessionId, type UserId, normalizeEmail } from "../domain/identity.js";
import type {
  CreateEmailAddressInput,
  CreatePasskeyCredentialInput,
  CreateRecoveryCodeInput,
  CreateRecoveryRequestInput,
  CreateSecurityEventInput,
  CreateSessionInput,
  CreateUserInput,
  IdentityStore,
  UpdatePasskeyUsageInput
} from "../domain/storage.js";
import type { Database } from "./client.js";
import {
  mapEmailAddress,
  mapPasskeyCredential,
  mapRecoveryCode,
  mapRecoveryRequest,
  mapSecurityEvent,
  mapSession,
  mapUser
} from "./mappers.js";
import {
  emailAddresses,
  passkeyCredentials,
  recoveryCodes,
  recoveryRequests,
  securityEvents,
  sessions,
  users
} from "./schema.js";

export class PostgresIdentityStore implements IdentityStore {
  constructor(private readonly db: Database) {}

  async createUser(input: CreateUserInput) {
    const [user] = await this.db
      .insert(users)
      .values({
        displayName: input.displayName ?? null
      })
      .returning();

    return mapUser(user);
  }

  async findUserById(userId: UserId) {
    const [user] = await this.db.select().from(users).where(eq(users.id, userId)).limit(1);

    return user ? mapUser(user) : null;
  }

  async createEmailAddress(input: CreateEmailAddressInput) {
    const verified = input.verified ?? false;
    const [emailAddress] = await this.db
      .insert(emailAddresses)
      .values({
        userId: input.userId,
        email: normalizeEmail(input.email),
        verified,
        verifiedAt: verified ? new Date() : null
      })
      .returning();

    return mapEmailAddress(emailAddress);
  }

  async findUserByEmail(email: string) {
    const normalizedEmail = normalizeEmail(email);
    const [row] = await this.db
      .select({ user: users })
      .from(emailAddresses)
      .innerJoin(users, eq(emailAddresses.userId, users.id))
      .where(eq(emailAddresses.email, normalizedEmail))
      .limit(1);

    return row ? mapUser(row.user) : null;
  }

  async markEmailVerified(email: string, verifiedAt: Date) {
    await this.db
      .update(emailAddresses)
      .set({
        verified: true,
        verifiedAt
      })
      .where(eq(emailAddresses.email, normalizeEmail(email)));
  }

  async createPasskeyCredential(input: CreatePasskeyCredentialInput) {
    const [credential] = await this.db
      .insert(passkeyCredentials)
      .values({
        userId: input.userId,
        credentialId: input.credentialId,
        publicKey: input.publicKey,
        signCount: input.signCount,
        deviceName: input.deviceName ?? null
      })
      .returning();

    return mapPasskeyCredential(credential);
  }

  async findPasskeyByCredentialId(credentialId: string) {
    const [credential] = await this.db
      .select()
      .from(passkeyCredentials)
      .where(eq(passkeyCredentials.credentialId, credentialId))
      .limit(1);

    return credential ? mapPasskeyCredential(credential) : null;
  }

  async listPasskeysForUser(userId: UserId) {
    const credentials = await this.db
      .select()
      .from(passkeyCredentials)
      .where(eq(passkeyCredentials.userId, userId));

    return credentials.map(mapPasskeyCredential);
  }

  async updatePasskeyUsage(input: UpdatePasskeyUsageInput) {
    await this.db
      .update(passkeyCredentials)
      .set({
        signCount: input.signCount,
        lastUsedAt: input.usedAt
      })
      .where(eq(passkeyCredentials.credentialId, input.credentialId));
  }

  async revokePasskeyCredential(credentialId: string, revokedAt: Date) {
    await this.db
      .update(passkeyCredentials)
      .set({ revokedAt })
      .where(eq(passkeyCredentials.credentialId, credentialId));
  }

  async createSession(input: CreateSessionInput) {
    const [session] = await this.db
      .insert(sessions)
      .values({
        userId: input.userId,
        tokenHash: input.tokenHash,
        deviceLabel: input.deviceLabel ?? null,
        userAgent: input.userAgent ?? null,
        ipHash: input.ipHash ?? null,
        expiresAt: input.expiresAt
      })
      .returning();

    return mapSession(session);
  }

  async findSessionByTokenHash(tokenHash: string) {
    const [session] = await this.db
      .select()
      .from(sessions)
      .where(eq(sessions.tokenHash, tokenHash))
      .limit(1);

    return session ? mapSession(session) : null;
  }

  async listSessionsForUser(userId: UserId) {
    const rows = await this.db.select().from(sessions).where(eq(sessions.userId, userId));

    return rows.map(mapSession);
  }

  async revokeSession(sessionId: SessionId, revokedAt: Date) {
    await this.db.update(sessions).set({ revokedAt }).where(eq(sessions.id, sessionId));
  }

  async revokeUserSessions(userId: UserId, revokedAt: Date) {
    await this.db.update(sessions).set({ revokedAt }).where(eq(sessions.userId, userId));
  }

  async createRecoveryCode(input: CreateRecoveryCodeInput) {
    const [code] = await this.db
      .insert(recoveryCodes)
      .values({
        userId: input.userId,
        codeHash: input.codeHash
      })
      .returning();

    return mapRecoveryCode(code);
  }

  async findUnusedRecoveryCode(userId: UserId, codeHash: string) {
    const [code] = await this.db
      .select()
      .from(recoveryCodes)
      .where(
        and(
          eq(recoveryCodes.userId, userId),
          eq(recoveryCodes.codeHash, codeHash),
          isNull(recoveryCodes.usedAt)
        )
      )
      .limit(1);

    return code ? mapRecoveryCode(code) : null;
  }

  async markRecoveryCodeUsed(userId: UserId, codeHash: string, usedAt: Date) {
    await this.db
      .update(recoveryCodes)
      .set({ usedAt })
      .where(and(eq(recoveryCodes.userId, userId), eq(recoveryCodes.codeHash, codeHash)));
  }

  async createRecoveryRequest(input: CreateRecoveryRequestInput) {
    const [request] = await this.db
      .insert(recoveryRequests)
      .values({
        userId: input.userId,
        riskLevel: input.riskLevel,
        expiresAt: input.expiresAt
      })
      .returning();

    return mapRecoveryRequest(request);
  }

  async findActiveRecoveryRequest(userId: UserId, now: Date) {
    const [request] = await this.db
      .select()
      .from(recoveryRequests)
      .where(
        and(
          eq(recoveryRequests.userId, userId),
          eq(recoveryRequests.status, "pending"),
          gt(recoveryRequests.expiresAt, now)
        )
      )
      .limit(1);

    return request ? mapRecoveryRequest(request) : null;
  }

  async completeRecoveryRequest(userId: UserId, completedAt: Date) {
    await this.db
      .update(recoveryRequests)
      .set({
        status: "completed",
        completedAt
      })
      .where(and(eq(recoveryRequests.userId, userId), eq(recoveryRequests.status, "pending")));
  }

  async createSecurityEvent(input: CreateSecurityEventInput) {
    const [event] = await this.db
      .insert(securityEvents)
      .values({
        userId: input.userId,
        actorUserId: input.actorUserId,
        sessionId: input.sessionId,
        eventType: input.eventType,
        outcome: input.outcome,
        riskLevel: input.riskLevel,
        metadata: input.metadata,
        context: input.context
      })
      .returning();

    return mapSecurityEvent(event);
  }

  async listSecurityEventsForUser(userId: UserId, limit: number) {
    const events = await this.db
      .select()
      .from(securityEvents)
      .where(eq(securityEvents.userId, userId))
      .orderBy(desc(securityEvents.createdAt))
      .limit(limit);

    return events.map(mapSecurityEvent);
  }
}
