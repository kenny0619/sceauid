import { type PostgresJsDatabase, drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import type { AppConfig } from "../config.js";
import * as schema from "./schema.js";

export type Database = PostgresJsDatabase<typeof schema>;

export type DatabaseClient = {
  db: Database;
  close(): Promise<void>;
};

export function createDatabaseClient(config: Pick<AppConfig, "DATABASE_URL">): DatabaseClient {
  const client = postgres(config.DATABASE_URL, {
    max: 10,
    idle_timeout: 20,
    connect_timeout: 10
  });

  return {
    db: drizzle(client, { schema }),
    async close() {
      await client.end();
    }
  };
}
