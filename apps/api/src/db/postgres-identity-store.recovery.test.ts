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

  it("counts and marks unused recovery codes for a user", async () => {
    const user = await createTestUser(context);
    const otherUser = await context.store.createUser({
      displayName: "Other User"
    });
    const usedAt = new Date("2026-06-01T12:00:00.000Z");

    await context.store.createRecoveryCode({
      userId: user.id,
      codeHash: "code-hash-1"
    });
    await context.store.createRecoveryCode({
      userId: user.id,
      codeHash: "code-hash-2"
    });
    await context.store.createRecoveryCode({
      userId: otherUser.id,
      codeHash: "other-code-hash"
    });

    await expect(context.store.countUnusedRecoveryCodesForUser(user.id)).resolves.toBe(2);

    await context.store.markUnusedRecoveryCodesUsed(user.id, usedAt);

    await expect(context.store.countUnusedRecoveryCodesForUser(user.id)).resolves.toBe(0);
    await expect(context.store.countUnusedRecoveryCodesForUser(otherUser.id)).resolves.toBe(1);
    await expect(context.store.findUnusedRecoveryCode(user.id, "code-hash-1")).resolves.toBeNull();
  });

  it("consumes an unused recovery code once", async () => {
    const user = await createTestUser(context);
    const usedAt = new Date("2026-06-01T12:00:00.000Z");

    await context.store.createRecoveryCode({
      userId: user.id,
      codeHash: "code-hash"
    });

    await expect(context.store.consumeRecoveryCode(user.id, "code-hash", usedAt)).resolves.toBe(
      true
    );
    await expect(context.store.consumeRecoveryCode(user.id, "code-hash", usedAt)).resolves.toBe(
      false
    );
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

  it("finds recovery requests by id", async () => {
    const user = await createTestUser(context);
    const expiresAt = new Date("2026-06-01T12:05:00.000Z");

    const request = await context.store.createRecoveryRequest({
      userId: user.id,
      riskLevel: "medium",
      expiresAt
    });

    await expect(context.store.findRecoveryRequestById(request.id)).resolves.toMatchObject({
      id: request.id,
      status: "pending",
      riskLevel: "medium",
      expiresAt
    });
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

  it("completes active recovery requests by id", async () => {
    const user = await createTestUser(context);
    const completedAt = new Date("2026-06-01T12:01:00.000Z");
    const request = await context.store.createRecoveryRequest({
      userId: user.id,
      riskLevel: "medium",
      expiresAt: new Date("2026-06-01T12:05:00.000Z")
    });

    await expect(
      context.store.completeActiveRecoveryRequest(request.id, completedAt)
    ).resolves.toMatchObject({
      id: request.id,
      status: "completed",
      completedAt
    });
    await expect(
      context.store.completeActiveRecoveryRequest(request.id, completedAt)
    ).resolves.toBeNull();
  });

  it("cancels active recovery requests by id", async () => {
    const user = await createTestUser(context);
    const cancelledAt = new Date("2026-06-01T12:01:00.000Z");
    const request = await context.store.createRecoveryRequest({
      userId: user.id,
      riskLevel: "medium",
      expiresAt: new Date("2026-06-01T12:05:00.000Z")
    });

    await expect(
      context.store.cancelActiveRecoveryRequest(request.id, cancelledAt)
    ).resolves.toMatchObject({
      id: request.id,
      status: "cancelled",
      completedAt: null
    });
    await expect(
      context.store.cancelActiveRecoveryRequest(request.id, cancelledAt)
    ).resolves.toBeNull();
  });
});
