import { describe, expect, it } from "vitest";
import type { Session, SessionId, UserId } from "../domain/identity.js";
import type { CreateSessionInput, IdentityStore } from "../domain/storage.js";
import { DefaultSessionService } from "./session-service.js";
import type { SessionToken } from "./session-token.js";

function createFakeStore() {
  const createdSessions: CreateSessionInput[] = [];
  const revokedSessions: Array<{ sessionId: SessionId; revokedAt: Date }> = [];
  const revokedUsers: Array<{ userId: UserId; revokedAt: Date }> = [];
  const sessionsByTokenHash = new Map<string, Session>();
  const sessionsByUser = new Map<UserId, Session[]>();

  const store: Pick<
    IdentityStore,
    | "createSession"
    | "findSessionByTokenHash"
    | "listSessionsForUser"
    | "revokeSession"
    | "revokeUserSessions"
  > = {
    async createSession(input) {
      createdSessions.push(input);

      const session: Session = {
        id: "session-id" as SessionId,
        createdAt: new Date("2026-06-01T12:00:00.000Z"),
        revokedAt: null,
        ...input,
        deviceLabel: input.deviceLabel ?? null,
        userAgent: input.userAgent ?? null,
        ipHash: input.ipHash ?? null,
        authenticatedAt: input.authenticatedAt ?? new Date("2026-06-01T12:00:00.000Z")
      };

      sessionsByTokenHash.set(input.tokenHash, session);
      sessionsByUser.set(input.userId, [session]);

      return session;
    },
    async findSessionByTokenHash(tokenHash) {
      return sessionsByTokenHash.get(tokenHash) ?? null;
    },
    async listSessionsForUser(userId) {
      return sessionsByUser.get(userId) ?? [];
    },
    async revokeSession(sessionId, revokedAt) {
      revokedSessions.push({ sessionId, revokedAt });
    },
    async revokeUserSessions(userId, revokedAt) {
      revokedUsers.push({ userId, revokedAt });
    }
  };

  return {
    store,
    createdSessions,
    revokedSessions,
    revokedUsers,
    sessionsByTokenHash,
    sessionsByUser
  };
}

const now = new Date("2026-06-01T12:00:00.000Z");
const userId = "user-id" as UserId;
const token = "session-token" as SessionToken;
const tokenHash = "c101e911469c969171040b50d70543313cf968fdef5bacc780776f8fb399ab36";

describe("DefaultSessionService", () => {
  it("creates sessions with opaque tokens, hashed persistence, and request context", async () => {
    const { store, createdSessions } = createFakeStore();
    const service = new DefaultSessionService(store, {
      now: () => now,
      generateToken: () => token
    });

    const result = await service.create({
      userId,
      deviceLabel: "Safari on macOS",
      context: {
        ipHash: "ip-hash",
        userAgent: "test-agent"
      }
    });

    expect(result.token).toBe(token);
    expect(createdSessions[0]).toMatchObject({
      userId,
      tokenHash,
      deviceLabel: "Safari on macOS",
      userAgent: "test-agent",
      ipHash: "ip-hash",
      expiresAt: new Date("2026-07-01T12:00:00.000Z"),
      authenticatedAt: now
    });
  });

  it("authenticates active sessions by token hash", async () => {
    const { store } = createFakeStore();
    const service = new DefaultSessionService(store, {
      now: () => now,
      generateToken: () => token
    });

    const { session } = await service.create({ userId });

    await expect(service.authenticate(token)).resolves.toEqual(session);
  });

  it("rejects expired and revoked sessions during authentication", async () => {
    const { store, sessionsByTokenHash } = createFakeStore();
    const service = new DefaultSessionService(store, {
      now: () => now,
      generateToken: () => token
    });

    await service.create({ userId, ttlSeconds: 60 });
    await expect(service.authenticate(token)).resolves.not.toBeNull();

    const expiredService = new DefaultSessionService(store, {
      now: () => new Date("2026-06-01T12:01:01.000Z"),
      generateToken: () => token
    });
    await expect(expiredService.authenticate(token)).resolves.toBeNull();

    const session = sessionsByTokenHash.get(tokenHash);
    if (!session) {
      throw new Error("Expected test session to exist");
    }

    sessionsByTokenHash.set(tokenHash, {
      ...session,
      revokedAt: new Date("2026-06-01T12:00:30.000Z")
    });

    await expect(service.authenticate(token)).resolves.toBeNull();
  });

  it("revokes one session and all user sessions with the current timestamp", async () => {
    const { store, revokedSessions, revokedUsers } = createFakeStore();
    const service = new DefaultSessionService(store, {
      now: () => now,
      generateToken: () => token
    });
    const sessionId = "session-id" as SessionId;

    await service.revoke(sessionId);
    await service.revokeAllForUser(userId);

    expect(revokedSessions).toEqual([{ sessionId, revokedAt: now }]);
    expect(revokedUsers).toEqual([{ userId, revokedAt: now }]);
  });
});
