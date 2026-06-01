import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import postgres from "postgres";
import { loadConfig } from "../config.js";

type Migration = {
  name: string;
  sql: string;
};

const migrationDirectory = new URL("../../drizzle", import.meta.url);

async function listMigrations(): Promise<Migration[]> {
  const files = await readdir(migrationDirectory);
  const sqlFiles = files.filter((file) => file.endsWith(".sql")).sort();

  return Promise.all(
    sqlFiles.map(async (name) => ({
      name,
      sql: await readFile(join(migrationDirectory.pathname, name), "utf8")
    }))
  );
}

function splitStatements(sql: string): string[] {
  return sql
    .split("--> statement-breakpoint")
    .map((statement) => statement.trim())
    .filter(Boolean);
}

async function migrate() {
  const config = loadConfig();
  const client = postgres(config.DATABASE_URL, {
    max: 1,
    idle_timeout: 5,
    connect_timeout: 10
  });

  try {
    await client`
      create table if not exists drizzle_migrations (
        id serial primary key,
        name text not null unique,
        applied_at timestamp with time zone not null default now()
      )
    `;

    const appliedRows = await client<{ name: string }[]>`
      select name from drizzle_migrations
    `;
    const applied = new Set(appliedRows.map((row) => row.name));
    const migrations = await listMigrations();

    for (const migration of migrations) {
      if (applied.has(migration.name)) {
        console.log(`Skipping already applied migration: ${migration.name}`);
        continue;
      }

      console.log(`Applying migration: ${migration.name}`);

      await client.begin(async (transaction) => {
        for (const statement of splitStatements(migration.sql)) {
          await transaction.unsafe(statement);
        }

        await transaction`
          insert into drizzle_migrations (name)
          values (${migration.name})
        `;
      });
    }

    console.log("Migrations complete");
  } finally {
    await client.end();
  }
}

await migrate();
