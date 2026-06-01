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

describe("PostgresIdentityStore passkeys", () => {
  it("creates and finds passkey credentials by credential id", async () => {
    const user = await createTestUser(context);
    const credential = await context.store.createPasskeyCredential({
      userId: user.id,
      credentialId: "credential-1",
      publicKey: "public-key",
      signCount: 1,
      deviceName: "MacBook"
    });

    await expect(context.store.findPasskeyByCredentialId("credential-1")).resolves.toMatchObject({
      id: credential.id,
      userId: user.id,
      publicKey: "public-key",
      signCount: 1,
      deviceName: "MacBook",
      revokedAt: null
    });
  });

  it("lists passkeys for a user", async () => {
    const user = await createTestUser(context);
    const otherUser = await context.store.createUser({ displayName: "Other User" });

    await context.store.createPasskeyCredential({
      userId: user.id,
      credentialId: "credential-1",
      publicKey: "public-key-1",
      signCount: 1
    });
    await context.store.createPasskeyCredential({
      userId: otherUser.id,
      credentialId: "credential-2",
      publicKey: "public-key-2",
      signCount: 1
    });

    await expect(context.store.listPasskeysForUser(user.id)).resolves.toHaveLength(1);
  });

  it("updates usage metadata and revokes credentials", async () => {
    const user = await createTestUser(context);
    await context.store.createPasskeyCredential({
      userId: user.id,
      credentialId: "credential-1",
      publicKey: "public-key",
      signCount: 1
    });

    const usedAt = new Date("2026-06-01T12:00:00.000Z");
    const revokedAt = new Date("2026-06-01T13:00:00.000Z");

    await context.store.updatePasskeyUsage({
      credentialId: "credential-1",
      signCount: 2,
      usedAt
    });
    await context.store.revokePasskeyCredential("credential-1", revokedAt);

    await expect(context.store.findPasskeyByCredentialId("credential-1")).resolves.toMatchObject({
      signCount: 2,
      lastUsedAt: usedAt,
      revokedAt
    });
  });
});
