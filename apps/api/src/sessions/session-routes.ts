import type { FastifyInstance } from "fastify";
import type { UserId } from "../domain/identity.js";
import type { IdentityStore } from "../domain/storage.js";
import type { SessionService } from "./session-service.js";

export type SessionRoutesDependencies = {
  sessionCookieName: string;
  sessionService: Pick<SessionService, "authenticate">;
  store: Pick<IdentityStore, "findUserById">;
};

export async function registerSessionRoutes(
  app: FastifyInstance,
  dependencies: SessionRoutesDependencies
): Promise<void> {
  app.get("/v1/sessions/current", async (request, reply) => {
    const token = request.cookies[dependencies.sessionCookieName];

    if (!token) {
      return reply.status(401).send({
        error: "unauthenticated",
        message: "Session cookie was not found"
      });
    }

    const session = await dependencies.sessionService.authenticate(token);

    if (!session) {
      return reply.status(401).send({
        error: "unauthenticated",
        message: "Session is invalid or expired"
      });
    }

    const user = await dependencies.store.findUserById(session.userId as UserId);

    if (!user) {
      return reply.status(401).send({
        error: "unauthenticated",
        message: "Session user was not found"
      });
    }

    return reply.send({
      user: {
        id: user.id,
        displayName: user.displayName,
        status: user.status
      },
      session: {
        id: session.id,
        deviceLabel: session.deviceLabel,
        userAgent: session.userAgent,
        expiresAt: session.expiresAt.toISOString(),
        createdAt: session.createdAt.toISOString()
      }
    });
  });
}
