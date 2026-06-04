import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { createPostgresStoreTestContext, createTestUser } from "../db/postgres-test-harness.js";
import { DefaultSecurityEventService } from "./security-event-service.js";

const context = createPostgresStoreTestContext();
const service = new DefaultSecurityEventService(context.store);

afterAll(async () => {
  await context.cleanup();
  await context.client.close();
});

beforeEach(async () => {
  await context.cleanup();
});

describe("DefaultSecurityEventService integration", () => {
  it("persists security events with defaults and sanitized request data", async () => {
    const user = await createTestUser(context);

    await service.record({
      userId: user.id,
      actorUserId: user.id,
      eventType: "login_failed",
      outcome: "failure",
      metadata: {
        method: "passkey",
        ignored: undefined
      },
      context: {
        ipHash: "ip-hash",
        userAgent: "test-agent",
        traceId: "trace-id"
      }
    });

    const page = await service.listForUser(user.id);

    expect(page.events).toHaveLength(1);
    expect(page.events[0]).toMatchObject({
      userId: user.id,
      actorUserId: user.id,
      sessionId: null,
      eventType: "login_failed",
      outcome: "failure",
      riskLevel: "low",
      metadata: { method: "passkey" },
      context: {
        ipHash: "ip-hash",
        userAgent: "test-agent",
        traceId: "trace-id"
      }
    });
  });
});
