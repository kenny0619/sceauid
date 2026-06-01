import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { createPostgresStoreTestContext } from "./postgres-test-harness.js";

const context = createPostgresStoreTestContext();

afterAll(async () => {
  await context.cleanup();
  await context.client.close();
});

beforeEach(async () => {
  await context.cleanup();
});

describe("PostgresIdentityStore users and emails", () => {
  it("creates users and finds them by id", async () => {
    const user = await context.store.createUser({ displayName: "Ibukun" });

    await expect(context.store.findUserById(user.id)).resolves.toMatchObject({
      id: user.id,
      displayName: "Ibukun",
      status: "active"
    });
  });

  it("normalizes email addresses and finds users by email", async () => {
    const user = await context.store.createUser({ displayName: null });
    const email = await context.store.createEmailAddress({
      userId: user.id,
      email: "  USER@Example.COM "
    });

    expect(email.email).toBe("user@example.com");

    await expect(context.store.findUserByEmail("user@example.com")).resolves.toMatchObject({
      id: user.id
    });
    await expect(context.store.findUserByEmail("USER@EXAMPLE.COM")).resolves.toMatchObject({
      id: user.id
    });
  });

  it("marks email addresses as verified", async () => {
    const user = await context.store.createUser({ displayName: null });
    await context.store.createEmailAddress({
      userId: user.id,
      email: "user@example.com"
    });

    const verifiedAt = new Date("2026-06-01T12:00:00.000Z");
    await context.store.markEmailVerified("USER@example.com", verifiedAt);

    const [row] = await context.client.db.execute<{
      verified: boolean;
      verified_at: Date | string | null;
    }>(`
      select verified, verified_at
      from email_addresses
      where email = 'user@example.com'
    `);

    expect(row.verified).toBe(true);
    expect(new Date(row.verified_at ?? "")).toEqual(verifiedAt);
  });
});
