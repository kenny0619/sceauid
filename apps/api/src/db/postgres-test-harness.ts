import type { User } from "../domain/identity.js";
import type { DatabaseClient } from "./client.js";
import { createDatabaseClient } from "./client.js";
import { PostgresIdentityStore } from "./postgres-identity-store.js";

export type PostgresStoreTestContext = {
  client: DatabaseClient;
  store: PostgresIdentityStore;
  cleanup(): Promise<void>;
};

const testDatabaseUrl =
  process.env.DATABASE_URL ?? "postgres://sceauid:sceauid@localhost:55432/sceauid";

export function createPostgresStoreTestContext(): PostgresStoreTestContext {
  const client = createDatabaseClient({ DATABASE_URL: testDatabaseUrl });

  return {
    client,
    store: new PostgresIdentityStore(client.db),
    async cleanup() {
      await client.db.execute(`
        truncate table
          security_events,
          recovery_requests,
          recovery_codes,
          sessions,
          passkey_credentials,
          email_addresses,
          users
        restart identity cascade
      `);
    }
  };
}

export async function createTestUser(context: PostgresStoreTestContext): Promise<User> {
  return context.store.createUser({ displayName: "Test User" });
}
