import type { FastifyInstance } from "fastify";

export type ReadinessCheck = {
  name: string;
  check(): Promise<void>;
};

export type HealthRoutesDependencies = {
  checks: ReadinessCheck[];
  now?: () => Date;
  serviceName?: string;
};

type ReadinessCheckResult = {
  durationMs: number;
  name: string;
  status: "down" | "up";
};

const defaultServiceName = "sceauid-api";

async function runReadinessCheck(
  check: ReadinessCheck,
  now: () => Date
): Promise<ReadinessCheckResult> {
  const startedAt = now().getTime();

  try {
    await check.check();

    return {
      durationMs: now().getTime() - startedAt,
      name: check.name,
      status: "up"
    };
  } catch {
    return {
      durationMs: now().getTime() - startedAt,
      name: check.name,
      status: "down"
    };
  }
}

export async function registerHealthRoutes(
  app: FastifyInstance,
  dependencies: HealthRoutesDependencies
): Promise<void> {
  const now = dependencies.now ?? (() => new Date());
  const service = dependencies.serviceName ?? defaultServiceName;

  app.get("/health", async () => ({
    status: "ok",
    service
  }));

  app.get("/ready", async (_request, reply) => {
    const checks = await Promise.all(
      dependencies.checks.map((check) => runReadinessCheck(check, now))
    );
    const ready = checks.every((check) => check.status === "up");

    return reply.status(ready ? 200 : 503).send({
      status: ready ? "ready" : "not_ready",
      service,
      checks
    });
  });
}
