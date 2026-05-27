import { describe, expect, it } from "vitest";
import { mapSecurityEvent, mapSession, mapUser } from "./mappers.js";

describe("database mappers", () => {
  it("maps users without leaking database naming into the domain", () => {
    const now = new Date("2026-05-27T10:00:00.000Z");

    expect(
      mapUser({
        id: "user-id",
        displayName: "Ibukun",
        status: "active",
        createdAt: now,
        updatedAt: now
      })
    ).toEqual({
      id: "user-id",
      displayName: "Ibukun",
      status: "active",
      createdAt: now,
      updatedAt: now
    });
  });

  it("maps sessions with nullable revocation state", () => {
    const now = new Date("2026-05-27T10:00:00.000Z");
    const expiresAt = new Date("2026-05-27T11:00:00.000Z");

    expect(
      mapSession({
        id: "session-id",
        userId: "user-id",
        tokenHash: "token-hash",
        deviceLabel: null,
        userAgent: "test-agent",
        ipHash: null,
        expiresAt,
        revokedAt: null,
        createdAt: now
      })
    ).toMatchObject({
      id: "session-id",
      userId: "user-id",
      tokenHash: "token-hash",
      revokedAt: null
    });
  });

  it("guards security event metadata and context shapes", () => {
    const now = new Date("2026-05-27T10:00:00.000Z");

    expect(
      mapSecurityEvent({
        id: "event-id",
        userId: null,
        actorUserId: null,
        sessionId: null,
        eventType: "login_failed",
        outcome: "failure",
        riskLevel: "medium",
        metadata: ["not", "an", "object"],
        context: null,
        createdAt: now
      })
    ).toMatchObject({
      metadata: {},
      context: {}
    });
  });
});
