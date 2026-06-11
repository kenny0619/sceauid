import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { registerRequestContext } from "./request-context.js";

async function createApp() {
  const app = Fastify({
    logger: false,
    requestIdHeader: "x-request-id"
  });

  await registerRequestContext(app);

  return app;
}

describe("request context", () => {
  it("attaches request ids to successful responses", async () => {
    const app = await createApp();
    app.get("/ok", async () => ({ ok: true }));

    const response = await app.inject({
      method: "GET",
      url: "/ok",
      headers: {
        "x-request-id": "req_test_123"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers["x-request-id"]).toBe("req_test_123");
    expect(response.json()).toEqual({ ok: true });

    await app.close();
  });

  it("returns generic internal error responses with request ids", async () => {
    const app = await createApp();
    app.get("/boom", async () => {
      throw new Error("Database password leaked in stack trace");
    });

    const response = await app.inject({
      method: "GET",
      url: "/boom",
      headers: {
        "x-request-id": "req_failure_123"
      }
    });

    expect(response.statusCode).toBe(500);
    expect(response.headers["x-request-id"]).toBe("req_failure_123");
    expect(response.json()).toEqual({
      error: "internal_server_error",
      message: "Unexpected server error",
      requestId: "req_failure_123"
    });

    await app.close();
  });

  it("preserves client error messages for framework validation failures", async () => {
    const app = await createApp();
    app.get(
      "/bad",
      {
        schema: {
          querystring: {
            type: "object",
            required: ["email"],
            properties: {
              email: {
                type: "string"
              }
            }
          }
        }
      },
      async () => ({ ok: true })
    );

    const response = await app.inject({
      method: "GET",
      url: "/bad",
      headers: {
        "x-request-id": "req_bad_123"
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.headers["x-request-id"]).toBe("req_bad_123");
    expect(response.json()).toMatchObject({
      error: "request_failed",
      requestId: "req_bad_123"
    });

    await app.close();
  });
});
