import type { RequestContext, Session, SessionId, UserId } from "../domain/identity.js";
import { isSessionActive } from "../domain/identity.js";
import type { IdentityStore } from "../domain/storage.js";
import { type SessionToken, generateSessionToken, hashSessionToken } from "./session-token.js";

export type CreateSessionServiceInput = {
  userId: UserId;
  deviceLabel?: string | null;
  context?: RequestContext;
  ttlSeconds?: number;
};

export type CreatedSession = {
  session: Session;
  token: SessionToken;
};

export type SessionService = {
  create(input: CreateSessionServiceInput): Promise<CreatedSession>;
  authenticate(token: string): Promise<Session | null>;
  listForUser(userId: UserId): Promise<Session[]>;
  revoke(sessionId: SessionId): Promise<void>;
  revokeAllForUser(userId: UserId): Promise<void>;
};

export type SessionServiceOptions = {
  ttlSeconds?: number;
  now?: () => Date;
  generateToken?: () => SessionToken;
};

const defaultTtlSeconds = 60 * 60 * 24 * 30;

function resolveTtlSeconds(ttlSeconds: number | undefined): number {
  if (ttlSeconds === undefined) {
    return defaultTtlSeconds;
  }

  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1) {
    throw new Error("Session TTL must be a positive integer number of seconds");
  }

  return ttlSeconds;
}

function resolveExpiresAt(now: Date, ttlSeconds: number): Date {
  return new Date(now.getTime() + ttlSeconds * 1000);
}

export class DefaultSessionService implements SessionService {
  private readonly ttlSeconds: number;
  private readonly now: () => Date;
  private readonly generateToken: () => SessionToken;

  constructor(
    private readonly store: Pick<
      IdentityStore,
      | "createSession"
      | "findSessionByTokenHash"
      | "listSessionsForUser"
      | "revokeSession"
      | "revokeUserSessions"
    >,
    options: SessionServiceOptions = {}
  ) {
    this.ttlSeconds = resolveTtlSeconds(options.ttlSeconds);
    this.now = options.now ?? (() => new Date());
    this.generateToken = options.generateToken ?? (() => generateSessionToken());
  }

  async create(input: CreateSessionServiceInput): Promise<CreatedSession> {
    const ttlSeconds = resolveTtlSeconds(input.ttlSeconds ?? this.ttlSeconds);
    const token = this.generateToken();
    const now = this.now();
    const session = await this.store.createSession({
      userId: input.userId,
      tokenHash: hashSessionToken(token),
      deviceLabel: input.deviceLabel ?? null,
      userAgent: input.context?.userAgent ?? null,
      ipHash: input.context?.ipHash ?? null,
      expiresAt: resolveExpiresAt(now, ttlSeconds),
      authenticatedAt: now
    });

    return { session, token };
  }

  async authenticate(token: string): Promise<Session | null> {
    const session = await this.store.findSessionByTokenHash(hashSessionToken(token));

    if (!session || !isSessionActive(session, this.now())) {
      return null;
    }

    return session;
  }

  async listForUser(userId: UserId): Promise<Session[]> {
    return this.store.listSessionsForUser(userId);
  }

  async revoke(sessionId: SessionId): Promise<void> {
    await this.store.revokeSession(sessionId, this.now());
  }

  async revokeAllForUser(userId: UserId): Promise<void> {
    await this.store.revokeUserSessions(userId, this.now());
  }
}
