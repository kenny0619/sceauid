import type { OutgoingHttpHeaders } from "node:http";
import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { registerRequestContext } from "./request-context.js";
import { registerSecurityHeaders } from "./security-headers.js";

async function createApp() {
  const app = Fastify({
    logger: false
  });

  await registerRequestContext(app);
  await registerSecurityHeaders(app);

  return app;
}

function expectSecurityHeaders(headers: OutgoingHttpHeaders) {
  expect(headers["cache-control"]).toBe("no-store");
  expect(headers["cross-origin-opener-policy"]).toBe("same-origin");
  expect(headers["referrer-policy"]).toBe("no-referrer");
  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["x-frame-options"]).toBe("DENY");
}

describe("security headers", () => {
  it("adds security headers to successful responses", async () => {
    const app = await createApp();
    app.get("/ok", async () => ({ ok: true }));

    const response = await app.inject({
      method: "GET",
      url: "/ok"
    });

    expect(response.statusCode).toBe(200);
    expectSecurityHeaders(response.headers);

    await app.close();
  });

  it("adds security headers to error responses", async () => {
    const app = await createApp();
    app.get("/boom", async () => {
      throw new Error("Unexpected failure");
    });

    const response = await app.inject({
      method: "GET",
      url: "/boom"
    });

    expect(response.statusCode).toBe(500);
    expectSecurityHeaders(response.headers);

    await app.close();
  });
});
