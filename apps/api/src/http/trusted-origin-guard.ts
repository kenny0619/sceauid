import type { FastifyInstance, FastifyRequest } from "fastify";

export type TrustedOriginGuardOptions = {
  sessionCookieName: string;
  trustedOrigins: string[];
};

const unsafeMethods = new Set(["DELETE", "PATCH", "POST", "PUT"]);

function normalizeOrigin(origin: string): string | null {
  try {
    return new URL(origin).origin;
  } catch {
    return null;
  }
}

function readHeader(request: FastifyRequest, name: string): string | null {
  const value = request.headers[name];

  if (Array.isArray(value)) {
    return value[0] ?? null;
  }

  return value ?? null;
}

function hasSessionCookie(request: FastifyRequest, sessionCookieName: string): boolean {
  const cookieHeader = readHeader(request, "cookie");

  if (!cookieHeader) {
    return false;
  }

  return cookieHeader
    .split(";")
    .some((cookie) => cookie.trim().startsWith(`${sessionCookieName}=`));
}

function hasTrustedOrigin(request: FastifyRequest, trustedOrigins: Set<string>): boolean {
  const origin = readHeader(request, "origin");

  if (!origin) {
    return false;
  }

  const normalizedOrigin = normalizeOrigin(origin);

  return normalizedOrigin ? trustedOrigins.has(normalizedOrigin) : false;
}

export async function registerTrustedOriginGuard(
  app: FastifyInstance,
  options: TrustedOriginGuardOptions
): Promise<void> {
  const trustedOrigins = new Set(
    options.trustedOrigins
      .map((origin) => normalizeOrigin(origin))
      .filter((origin) => origin !== null)
  );

  app.addHook("preHandler", async (request, reply) => {
    if (!unsafeMethods.has(request.method)) {
      return;
    }

    if (!hasSessionCookie(request, options.sessionCookieName)) {
      return;
    }

    if (hasTrustedOrigin(request, trustedOrigins)) {
      return;
    }

    return reply.status(403).send({
      error: "csrf_origin_rejected",
      message: "Request origin is not trusted"
    });
  });
}
