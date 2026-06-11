import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { type ReadinessCheck, registerHealthRoutes } from "./health-routes.js";

function createClock() {
  let timestamp = Date.parse("2026-06-01T12:00:00.000Z");

  return () => {
    timestamp += 7;
    return new Date(timestamp);
  };
}

async function createApp(checks: ReadinessCheck[]) {
  const app = Fastify();

  await registerHealthRoutes(app, {
    checks,
    now: createClock()
  });

  return app;
}

describe("health routes", () => {
  it("returns liveness without checking dependencies", async () => {
    let checked = false;
    const app = await createApp([
      {
        name: "postgres",
        async check() {
          checked = true;
        }
      }
    ]);

    const response = await app.inject({
      method: "GET",
      url: "/health"
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      status: "ok",
      service: "sceauid-api"
    });
    expect(checked).toBe(false);

    await app.close();
  });

  it("returns ready when every dependency check passes", async () => {
    const app = await createApp([
      {
        name: "postgres",
        async check() {}
      },
      {
        name: "redis:challenges",
        async check() {}
      }
    ]);

    const response = await app.inject({
      method: "GET",
      url: "/ready"
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      status: "ready",
      service: "sceauid-api",
      checks: [
        {
          durationMs: 14,
          name: "postgres",
          status: "up"
        },
        {
          durationMs: 14,
          name: "redis:challenges",
          status: "up"
        }
      ]
    });

    await app.close();
  });

  it("returns not ready when any dependency check fails", async () => {
    const app = await createApp([
      {
        name: "postgres",
        async check() {}
      },
      {
        name: "redis:risk",
        async check() {
          throw new Error("Redis unavailable");
        }
      }
    ]);

    const response = await app.inject({
      method: "GET",
      url: "/ready"
    });

    expect(response.statusCode).toBe(503);
    expect(response.json()).toEqual({
      status: "not_ready",
      service: "sceauid-api",
      checks: [
        {
          durationMs: 14,
          name: "postgres",
          status: "up"
        },
        {
          durationMs: 14,
          name: "redis:risk",
          status: "down"
        }
      ]
    });

    await app.close();
  });
});
