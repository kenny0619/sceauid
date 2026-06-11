import cookie from "@fastify/cookie";
import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { clearSessionCookie, setSessionCookie } from "./session-cookie.js";

describe("session cookie helpers", () => {
  it("sets HTTP-only session cookies with secure defaults", async () => {
    const app = Fastify();
    await app.register(cookie);
    app.get("/login", async (_request, reply) => {
      setSessionCookie(
        reply,
        {
          name: "sceauid_session",
          secure: true
        },
        "session-token",
        new Date("2026-07-01T12:00:00.000Z")
      );

      return { ok: true };
    });

    const response = await app.inject({
      method: "GET",
      url: "/login"
    });

    expect(response.headers["set-cookie"]).toContain("sceauid_session=session-token");
    expect(response.headers["set-cookie"]).toContain("Path=/");
    expect(response.headers["set-cookie"]).toContain("HttpOnly");
    expect(response.headers["set-cookie"]).toContain("Secure");
    expect(response.headers["set-cookie"]).toContain("SameSite=Lax");

    await app.close();
  });

  it("clears session cookies with the same security attributes", async () => {
    const app = Fastify();
    await app.register(cookie);
    app.get("/logout", async (_request, reply) => {
      clearSessionCookie(reply, {
        name: "sceauid_session",
        secure: true
      });

      return { ok: true };
    });

    const response = await app.inject({
      method: "GET",
      url: "/logout"
    });

    expect(response.headers["set-cookie"]).toContain("sceauid_session=;");
    expect(response.headers["set-cookie"]).toContain("Path=/");
    expect(response.headers["set-cookie"]).toContain("HttpOnly");
    expect(response.headers["set-cookie"]).toContain("Secure");
    expect(response.headers["set-cookie"]).toContain("SameSite=Lax");

    await app.close();
  });
});
