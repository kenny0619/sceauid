import { z } from "zod";

const productionRequiredKeys = [
  "DATABASE_URL",
  "REDIS_URL",
  "APP_ORIGIN",
  "WEBAUTHN_RP_ID"
] as const;

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

const productionConfigSchema = envSchema.superRefine((config, context) => {
  const appOrigin = new URL(config.APP_ORIGIN);

  if (appOrigin.protocol !== "https:") {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "APP_ORIGIN must use https in production",
      path: ["APP_ORIGIN"]
    });
  }

  if (config.WEBAUTHN_RP_ID === "localhost") {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "WEBAUTHN_RP_ID must not be localhost in production",
      path: ["WEBAUTHN_RP_ID"]
    });
  }
});

function assertProductionEnvKeys(env: NodeJS.ProcessEnv): void {
  const missingKeys = productionRequiredKeys.filter((key) => !env[key]);

  if (missingKeys.length > 0) {
    throw new Error(`${missingKeys.join(", ")} must be explicitly set in production`);
  }
}

export type AppConfig = z.infer<typeof envSchema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const config = envSchema.parse(env);

  if (config.NODE_ENV !== "production") {
    return config;
  }

  assertProductionEnvKeys(env);

  return productionConfigSchema.parse(env);
}
