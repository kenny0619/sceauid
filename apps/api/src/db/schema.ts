import {
  boolean,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid
} from "drizzle-orm/pg-core";

export const userStatus = pgEnum("user_status", ["active", "disabled", "pending_recovery"]);

export const recoveryRequestStatus = pgEnum("recovery_request_status", [
  "pending",
  "verified",
  "completed",
  "expired",
  "cancelled"
]);

export const riskLevel = pgEnum("risk_level", ["low", "medium", "high"]);

export const securityEventOutcome = pgEnum("security_event_outcome", [
  "success",
  "failure",
  "pending"
]);

export const securityEventType = pgEnum("security_event_type", [
  "signup_started",
  "email_verified",
  "passkey_registered",
  "passkey_removed",
  "login_succeeded",
  "login_failed",
  "session_created",
  "session_revoked",
  "recovery_started",
  "recovery_verified",
  "recovery_completed",
  "recovery_delayed",
  "rate_limit_triggered",
  "suspicious_activity_flagged"
]);

const timestamps = {
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow()
};

export const users = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),
  displayName: text("display_name"),
  status: userStatus("status").notNull().default("active"),
  ...timestamps
});

export const emailAddresses = pgTable(
  "email_addresses",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    email: text("email").notNull(),
    verified: boolean("verified").notNull().default(false),
    verifiedAt: timestamp("verified_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => ({
    emailUnique: uniqueIndex("email_addresses_email_unique").on(table.email),
    userIdIdx: index("email_addresses_user_id_idx").on(table.userId)
  })
);

export const passkeyCredentials = pgTable(
  "passkey_credentials",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    credentialId: text("credential_id").notNull(),
    publicKey: text("public_key").notNull(),
    signCount: integer("sign_count").notNull().default(0),
    deviceName: text("device_name"),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    revokedAt: timestamp("revoked_at", { withTimezone: true })
  },
  (table) => ({
    credentialIdUnique: uniqueIndex("passkey_credentials_credential_id_unique").on(
      table.credentialId
    ),
    userIdIdx: index("passkey_credentials_user_id_idx").on(table.userId)
  })
);

export const sessions = pgTable(
  "sessions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull(),
    deviceLabel: text("device_label"),
    userAgent: text("user_agent"),
    ipHash: text("ip_hash"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => ({
    tokenHashUnique: uniqueIndex("sessions_token_hash_unique").on(table.tokenHash),
    userIdIdx: index("sessions_user_id_idx").on(table.userId),
    expiresAtIdx: index("sessions_expires_at_idx").on(table.expiresAt)
  })
);

export const recoveryCodes = pgTable(
  "recovery_codes",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    codeHash: text("code_hash").notNull(),
    usedAt: timestamp("used_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => ({
    codeHashUnique: uniqueIndex("recovery_codes_code_hash_unique").on(table.codeHash),
    userIdIdx: index("recovery_codes_user_id_idx").on(table.userId)
  })
);

export const recoveryRequests = pgTable(
  "recovery_requests",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    status: recoveryRequestStatus("status").notNull().default("pending"),
    riskLevel: riskLevel("risk_level").notNull().default("low"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => ({
    userIdIdx: index("recovery_requests_user_id_idx").on(table.userId),
    statusIdx: index("recovery_requests_status_idx").on(table.status),
    expiresAtIdx: index("recovery_requests_expires_at_idx").on(table.expiresAt)
  })
);

export const securityEvents = pgTable(
  "security_events",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id").references(() => users.id, { onDelete: "set null" }),
    actorUserId: uuid("actor_user_id").references(() => users.id, { onDelete: "set null" }),
    sessionId: uuid("session_id").references(() => sessions.id, { onDelete: "set null" }),
    eventType: securityEventType("event_type").notNull(),
    outcome: securityEventOutcome("outcome").notNull(),
    riskLevel: riskLevel("risk_level").notNull().default("low"),
    metadata: jsonb("metadata").notNull().default({}),
    context: jsonb("context").notNull().default({}),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow()
  },
  (table) => ({
    userIdCreatedAtIdx: index("security_events_user_id_created_at_idx").on(
      table.userId,
      table.createdAt
    ),
    eventTypeIdx: index("security_events_event_type_idx").on(table.eventType),
    riskLevelIdx: index("security_events_risk_level_idx").on(table.riskLevel)
  })
);
