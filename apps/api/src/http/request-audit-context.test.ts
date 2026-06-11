import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { resolveRequestAuditContext } from "./request-audit-context.js";

describe("request audit context", () => {
  it("builds security-event context without storing raw IP addresses", async () => {
    const app = Fastify({
      requestIdHeader: "x-request-id"
    });
    app.get("/context", async (request) => resolveRequestAuditContext(request));

    const response = await app.inject({
      method: "GET",
      url: "/context",
      headers: {
        "user-agent": "test-agent",
        "x-request-id": "trace-id"
      },
      remoteAddress: "203.0.113.10"
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      ipHash: expect.stringMatching(/^[A-Za-z0-9_-]+$/),
      traceId: "trace-id",
      userAgent: "test-agent"
    });
    expect(response.json().ipHash).not.toBe("203.0.113.10");

    await app.close();
  });
});
