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

describe("PostgresIdentityStore recovery", () => {
  it("creates, finds, and marks recovery codes as used", async () => {
    const user = await createTestUser(context);
    const usedAt = new Date("2026-06-01T12:00:00.000Z");

    const code = await context.store.createRecoveryCode({
      userId: user.id,
      codeHash: "code-hash"
    });

    await expect(context.store.findUnusedRecoveryCode(user.id, "code-hash")).resolves.toMatchObject(
      {
        id: code.id,
        usedAt: null
      }
    );

    await context.store.markRecoveryCodeUsed(user.id, "code-hash", usedAt);

    await expect(context.store.findUnusedRecoveryCode(user.id, "code-hash")).resolves.toBeNull();
  });

  it("finds active pending recovery requests by user and expiry", async () => {
    const user = await createTestUser(context);
    const now = new Date("2026-06-01T12:00:00.000Z");
    const expiresAt = new Date("2026-06-01T12:05:00.000Z");

    const request = await context.store.createRecoveryRequest({
      userId: user.id,
      riskLevel: "medium",
      expiresAt
    });

    await expect(context.store.findActiveRecoveryRequest(user.id, now)).resolves.toMatchObject({
      id: request.id,
      status: "pending",
      riskLevel: "medium"
    });
    await expect(
      context.store.findActiveRecoveryRequest(user.id, new Date("2026-06-01T12:06:00.000Z"))
    ).resolves.toBeNull();
  });

  it("completes pending recovery requests", async () => {
    const user = await createTestUser(context);
    const now = new Date("2026-06-01T12:00:00.000Z");
    const completedAt = new Date("2026-06-01T12:01:00.000Z");

    await context.store.createRecoveryRequest({
      userId: user.id,
      riskLevel: "low",
      expiresAt: new Date("2026-06-01T12:05:00.000Z")
    });

    await context.store.completeRecoveryRequest(user.id, completedAt);

    await expect(context.store.findActiveRecoveryRequest(user.id, now)).resolves.toBeNull();
  });
});
