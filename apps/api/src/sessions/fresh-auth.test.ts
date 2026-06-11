import { describe, expect, it } from "vitest";
import type { Session, SessionId, UserId } from "../domain/identity.js";
import { isFreshAuthentication } from "./fresh-auth.js";

const session: Session = {
  id: "session-id" as SessionId,
  userId: "user-id" as UserId,
  tokenHash: "token-hash",
  deviceLabel: "Safari on macOS",
  userAgent: "test-agent",
  ipHash: null,
  expiresAt: new Date("2026-07-01T12:00:00.000Z"),
  revokedAt: null,
  authenticatedAt: new Date("2026-06-01T12:50:00.000Z"),
  createdAt: new Date("2026-06-01T12:00:00.000Z")
};

describe("fresh auth policy", () => {
  it("treats sessions inside the freshness window as recently authenticated", () => {
    expect(isFreshAuthentication(session, new Date("2026-06-01T13:00:00.000Z"))).toBe(true);
  });

  it("treats sessions outside the freshness window as stale", () => {
    expect(isFreshAuthentication(session, new Date("2026-06-01T13:00:01.000Z"))).toBe(false);
  });
});
