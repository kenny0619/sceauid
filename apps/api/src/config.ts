import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(4000),
  DATABASE_URL: z.string().url().default("postgres://sceauid:sceauid@localhost:55432/sceauid"),
  REDIS_URL: z.string().url().default("redis://localhost:6379"),
  SESSION_COOKIE_NAME: z.string().min(1).default("sceauid_session"),
  APP_ORIGIN: z.string().url().default("http://localhost:3000"),
  WEBAUTHN_RP_NAME: z.string().min(1).default("SceauID"),
  WEBAUTHN_RP_ID: z.string().min(1).default("localhost")
});

export type AppConfig = z.infer<typeof envSchema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  return envSchema.parse(env);
}
