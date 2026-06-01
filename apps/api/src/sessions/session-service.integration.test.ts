import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { createPostgresStoreTestContext, createTestUser } from "../db/postgres-test-harness.js";
import { DefaultSessionService } from "./session-service.js";
import type { SessionToken } from "./session-token.js";

const context = createPostgresStoreTestContext();
const now = new Date("2026-06-01T12:00:00.000Z");
const token = "session-token" as SessionToken;

afterAll(async () => {
  await context.cleanup();
  await context.client.close();
});

beforeEach(async () => {
  await context.cleanup();
});

describe("DefaultSessionService integration", () => {
  it("persists hashed sessions and authenticates only active tokens", async () => {
    const user = await createTestUser(context);
    const service = new DefaultSessionService(context.store, {
      now: () => now,
      generateToken: () => token
    });

    const { session } = await service.create({
      userId: user.id,
      deviceLabel: "Safari on macOS",
      context: {
        ipHash: "ip-hash",
        userAgent: "test-agent"
      }
    });

    expect(session.tokenHash).not.toBe(token);
    await expect(context.store.findSessionByTokenHash(token)).resolves.toBeNull();
    await expect(service.authenticate(token)).resolves.toMatchObject({
      id: session.id,
      userId: user.id,
      deviceLabel: "Safari on macOS",
      ipHash: "ip-hash",
      userAgent: "test-agent",
      revokedAt: null
    });

    await service.revoke(session.id);

    await expect(service.authenticate(token)).resolves.toBeNull();
  });
});
