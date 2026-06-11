import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { registerTrustedOriginGuard } from "./trusted-origin-guard.js";

async function createApp() {
  const app = Fastify();

  await registerTrustedOriginGuard(app, {
    sessionCookieName: "sceauid_session",
    trustedOrigins: ["https://app.example.com"]
  });
  app.get("/resource", async () => ({ ok: true }));
  app.post("/resource", async () => ({ ok: true }));
  app.delete("/resource", async () => ({ ok: true }));

  return app;
}

describe("trusted origin guard", () => {
  it("allows safe methods without origin checks", async () => {
    const app = await createApp();

    const response = await app.inject({
      method: "GET",
      url: "/resource",
      headers: {
        cookie: "sceauid_session=session_token"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ ok: true });

    await app.close();
  });

  it("allows unsafe requests that do not carry the session cookie", async () => {
    const app = await createApp();

    const response = await app.inject({
      method: "POST",
      url: "/resource"
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ ok: true });

    await app.close();
  });

  it("allows cookie-authenticated unsafe requests from trusted origins", async () => {
    const app = await createApp();

    const response = await app.inject({
      method: "POST",
      url: "/resource",
      headers: {
        cookie: "theme=light; sceauid_session=session_token",
        origin: "https://app.example.com/settings"
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ ok: true });

    await app.close();
  });

  it("rejects cookie-authenticated unsafe requests without an origin", async () => {
    const app = await createApp();

    const response = await app.inject({
      method: "DELETE",
      url: "/resource",
      headers: {
        cookie: "sceauid_session=session_token"
      }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({
      error: "csrf_origin_rejected",
      message: "Request origin is not trusted"
    });

    await app.close();
  });

  it("rejects cookie-authenticated unsafe requests from untrusted origins", async () => {
    const app = await createApp();

    const response = await app.inject({
      method: "POST",
      url: "/resource",
      headers: {
        cookie: "sceauid_session=session_token",
        origin: "https://evil.example"
      }
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({
      error: "csrf_origin_rejected",
      message: "Request origin is not trusted"
    });

    await app.close();
  });
});
