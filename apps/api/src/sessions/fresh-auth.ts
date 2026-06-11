import type { Session } from "../domain/identity.js";

export const defaultFreshAuthWindowSeconds = 60 * 10;

export type FreshAuthPolicy = {
  windowSeconds?: number;
};

export function isFreshAuthentication(
  session: Session,
  now: Date,
  policy: FreshAuthPolicy = {}
): boolean {
  const windowSeconds = policy.windowSeconds ?? defaultFreshAuthWindowSeconds;

  return now.getTime() - session.authenticatedAt.getTime() <= windowSeconds * 1000;
}

export function rejectFreshAuthRequired(reply: {
  status(statusCode: number): {
    send(payload: { error: string; message: string }): unknown;
  };
}) {
  return reply.status(403).send({
    error: "fresh_auth_required",
    message: "Recent authentication is required for this action"
  });
}
