import type { FastifyInstance } from "fastify";
import type { SessionService } from "../sessions/session-service.js";
import type { RecoveryCodeService } from "./recovery-code-service.js";

export type RecoveryRoutesDependencies = {
  recoveryCodes: RecoveryCodeService;
  sessionCookieName: string;
  sessionService: Pick<SessionService, "authenticate">;
};

async function authenticateRequest(
  request: { cookies: Record<string, string | undefined> },
  dependencies: Pick<RecoveryRoutesDependencies, "sessionCookieName" | "sessionService">,
  reply: {
    status(statusCode: number): {
      send(payload: { error: string; message: string }): unknown;
    };
  }
) {
  const token = request.cookies[dependencies.sessionCookieName];

  if (!token) {
    reply.status(401).send({
      error: "unauthenticated",
      message: "Session cookie was not found"
    });
    return null;
  }

  const session = await dependencies.sessionService.authenticate(token);

  if (!session) {
    reply.status(401).send({
      error: "unauthenticated",
      message: "Session is invalid or expired"
    });
    return null;
  }

  return session;
}

export async function registerRecoveryRoutes(
  app: FastifyInstance,
  dependencies: RecoveryRoutesDependencies
): Promise<void> {
  app.get("/v1/recovery/status", async (request, reply) => {
    const session = await authenticateRequest(request, dependencies, reply);

    if (!session) {
      return;
    }

    return reply.send(await dependencies.recoveryCodes.status(session.userId));
  });

  app.post("/v1/recovery/codes", async (request, reply) => {
    const session = await authenticateRequest(request, dependencies, reply);

    if (!session) {
      return;
    }

    return reply.send(await dependencies.recoveryCodes.enroll({ userId: session.userId }));
  });
}
