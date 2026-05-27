import { describe, expect, it } from "vitest";
import {
  type PasskeyCredential,
  type Session,
  isPasskeyActive,
  isSessionActive,
  normalizeEmail
} from "./identity.js";

describe("identity domain helpers", () => {
  it("normalizes email addresses for lookup and uniqueness", () => {
    expect(normalizeEmail("  User.Name+Test@Example.COM ")).toBe("user.name+test@example.com");
  });

  it("treats a non-expired non-revoked session as active", () => {
    const now = new Date("2026-05-27T10:00:00.000Z");
    const session = {
      revokedAt: null,
      expiresAt: new Date("2026-05-27T10:05:00.000Z")
    } as Session;

    expect(isSessionActive(session, now)).toBe(true);
  });

  it("treats expired or revoked sessions as inactive", () => {
    const now = new Date("2026-05-27T10:00:00.000Z");
    const expiredSession = {
      revokedAt: null,
      expiresAt: new Date("2026-05-27T09:59:59.000Z")
    } as Session;
    const revokedSession = {
      revokedAt: new Date("2026-05-27T09:50:00.000Z"),
      expiresAt: new Date("2026-05-27T10:05:00.000Z")
    } as Session;

    expect(isSessionActive(expiredSession, now)).toBe(false);
    expect(isSessionActive(revokedSession, now)).toBe(false);
  });

  it("treats passkeys as active until revoked", () => {
    expect(isPasskeyActive({ revokedAt: null } as PasskeyCredential)).toBe(true);
    expect(isPasskeyActive({ revokedAt: new Date() } as PasskeyCredential)).toBe(false);
  });
});
