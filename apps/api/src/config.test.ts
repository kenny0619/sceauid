import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";

describe("loadConfig", () => {
  it("uses development defaults for local runs", () => {
    expect(loadConfig({})).toEqual({
      NODE_ENV: "development",
      PORT: 4000,
      DATABASE_URL: "postgres://sceauid:sceauid@localhost:55432/sceauid",
      REDIS_URL: "redis://localhost:6379",
      SESSION_COOKIE_NAME: "sceauid_session",
      APP_ORIGIN: "http://localhost:3000",
      TRUST_PROXY: false,
      SECURITY_EVENT_RETENTION_DAYS: 365,
      WEBAUTHN_RP_NAME: "SceauID",
      WEBAUTHN_RP_ID: "localhost"
    });
  });

  it("coerces numeric ports and accepts explicit production config", () => {
    expect(
      loadConfig({
        NODE_ENV: "production",
        PORT: "8080",
        DATABASE_URL: "postgres://sceauid:secret@db.internal:5432/sceauid",
        REDIS_URL: "redis://redis.internal:6379",
        SESSION_COOKIE_NAME: "identity_session",
        APP_ORIGIN: "https://app.example.com",
        TRUST_PROXY: "true",
        SECURITY_EVENT_RETENTION_DAYS: "730",
        WEBAUTHN_RP_NAME: "Example App",
        WEBAUTHN_RP_ID: "app.example.com"
      })
    ).toEqual({
      NODE_ENV: "production",
      PORT: 8080,
      DATABASE_URL: "postgres://sceauid:secret@db.internal:5432/sceauid",
      REDIS_URL: "redis://redis.internal:6379",
      SESSION_COOKIE_NAME: "identity_session",
      APP_ORIGIN: "https://app.example.com",
      TRUST_PROXY: true,
      SECURITY_EVENT_RETENTION_DAYS: 730,
      WEBAUTHN_RP_NAME: "Example App",
      WEBAUTHN_RP_ID: "app.example.com"
    });
  });

  it("rejects invalid security event retention windows", () => {
    expect(() => loadConfig({ SECURITY_EVENT_RETENTION_DAYS: "0" })).toThrow();
    expect(() => loadConfig({ SECURITY_EVENT_RETENTION_DAYS: "3651" })).toThrow();
  });

  it("accepts explicit boolean-like trust proxy values", () => {
    expect(loadConfig({ TRUST_PROXY: "1" }).TRUST_PROXY).toBe(true);
    expect(loadConfig({ TRUST_PROXY: "true" }).TRUST_PROXY).toBe(true);
    expect(loadConfig({ TRUST_PROXY: "0" }).TRUST_PROXY).toBe(false);
    expect(loadConfig({ TRUST_PROXY: "false" }).TRUST_PROXY).toBe(false);
  });

  it("rejects missing production-critical config", () => {
    expect(() =>
      loadConfig({
        NODE_ENV: "production"
      })
    ).toThrow(
      "DATABASE_URL, REDIS_URL, APP_ORIGIN, WEBAUTHN_RP_ID must be explicitly set in production"
    );
  });

  it("rejects unsafe production origins and relying party ids", () => {
    expect(() =>
      loadConfig({
        NODE_ENV: "production",
        DATABASE_URL: "postgres://sceauid:secret@db.internal:5432/sceauid",
        REDIS_URL: "redis://redis.internal:6379",
        APP_ORIGIN: "http://app.example.com",
        WEBAUTHN_RP_ID: "localhost"
      })
    ).toThrow("APP_ORIGIN must use https in production");
  });

  it("rejects invalid URLs", () => {
    expect(() =>
      loadConfig({
        DATABASE_URL: "not-a-url"
      })
    ).toThrow();
  });
});
