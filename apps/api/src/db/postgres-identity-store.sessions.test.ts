import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { createPostgresStoreTestContext, createTestUser } from "./postgres-test-harness.js";

const context = createPostgresStoreTestContext();

afterAll(async () => {
  await context.cleanup();
  await context.client.close();
});

beforeEach(async () => {
  await context.cleanup();
});

describe("PostgresIdentityStore sessions", () => {
  it("creates and finds sessions by token hash", async () => {
    const user = await createTestUser(context);
    const expiresAt = new Date("2026-06-01T13:00:00.000Z");
    const authenticatedAt = new Date("2026-06-01T12:05:00.000Z");

    const session = await context.store.createSession({
      userId: user.id,
      tokenHash: "token-hash-1",
      deviceLabel: "Safari on macOS",
      userAgent: "test-agent",
      ipHash: "ip-hash",
      expiresAt,
      authenticatedAt
    });

    await expect(context.store.findSessionByTokenHash("token-hash-1")).resolves.toMatchObject({
      id: session.id,
      userId: user.id,
      deviceLabel: "Safari on macOS",
      expiresAt,
      authenticatedAt,
      revokedAt: null
    });
  });

  it("lists only sessions for the requested user", async () => {
    const user = await createTestUser(context);
    const otherUser = await context.store.createUser({ displayName: "Other User" });
    const expiresAt = new Date("2026-06-01T13:00:00.000Z");

    await context.store.createSession({ userId: user.id, tokenHash: "token-1", expiresAt });
    await context.store.createSession({ userId: otherUser.id, tokenHash: "token-2", expiresAt });

    await expect(context.store.listSessionsForUser(user.id)).resolves.toHaveLength(1);
  });

  it("revokes one session and all user sessions", async () => {
    const user = await createTestUser(context);
    const expiresAt = new Date("2026-06-01T13:00:00.000Z");
    const revokedAt = new Date("2026-06-01T12:30:00.000Z");

    const first = await context.store.createSession({
      userId: user.id,
      tokenHash: "token-1",
      expiresAt
    });
    await context.store.createSession({ userId: user.id, tokenHash: "token-2", expiresAt });

    await context.store.revokeSession(first.id, revokedAt);

    await expect(context.store.findSessionByTokenHash("token-1")).resolves.toMatchObject({
      revokedAt
    });
    await expect(context.store.findSessionByTokenHash("token-2")).resolves.toMatchObject({
      revokedAt: null
    });

    await context.store.revokeUserSessions(user.id, revokedAt);

    const sessions = await context.store.listSessionsForUser(user.id);
    expect(sessions.every((session) => session.revokedAt?.getTime() === revokedAt.getTime())).toBe(
      true
    );
  });

  it("deletes stale sessions in bounded batches", async () => {
    const user = await createTestUser(context);
    const cutoff = new Date("2026-06-01T12:00:00.000Z");
    const oldExpiresAt = new Date("2026-05-01T12:00:00.000Z");
    const futureExpiresAt = new Date("2026-07-01T12:00:00.000Z");
    const revokedAt = new Date("2026-05-15T12:00:00.000Z");

    const expired = await context.store.createSession({
      userId: user.id,
      tokenHash: "expired-token",
      expiresAt: oldExpiresAt
    });
    const revoked = await context.store.createSession({
      userId: user.id,
      tokenHash: "revoked-token",
      expiresAt: futureExpiresAt
    });
    const active = await context.store.createSession({
      userId: user.id,
      tokenHash: "active-token",
      expiresAt: futureExpiresAt
    });
    await context.store.revokeSession(revoked.id, revokedAt);

    await expect(context.store.deleteStaleSessions(cutoff, 1)).resolves.toBe(1);
    await expect(context.store.deleteStaleSessions(cutoff, 1)).resolves.toBe(1);
    await expect(context.store.deleteStaleSessions(cutoff, 1)).resolves.toBe(0);

    await expect(context.store.findSessionByTokenHash(expired.tokenHash)).resolves.toBeNull();
    await expect(context.store.findSessionByTokenHash(revoked.tokenHash)).resolves.toBeNull();
    await expect(context.store.findSessionByTokenHash(active.tokenHash)).resolves.toMatchObject({
      id: active.id
    });
  });
});
