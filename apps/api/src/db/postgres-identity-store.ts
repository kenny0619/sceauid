import { eq } from "drizzle-orm";
import { normalizeEmail, type UserId } from "../domain/identity.js";
import type { CreateEmailAddressInput, CreateUserInput, IdentityStore } from "../domain/storage.js";
import type { Database } from "./client.js";
import { mapEmailAddress, mapUser } from "./mappers.js";
import { emailAddresses, users } from "./schema.js";

export class PostgresIdentityStore
  implements
    Pick<
      IdentityStore,
      "createUser" | "findUserById" | "createEmailAddress" | "findUserByEmail" | "markEmailVerified"
    >
{
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
}
