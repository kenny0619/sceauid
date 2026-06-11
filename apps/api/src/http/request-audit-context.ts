import { createHash } from "node:crypto";
import type { FastifyRequest } from "fastify";
import type { RequestContext } from "../domain/identity.js";

function hashIp(ip: string): string {
  return createHash("sha256").update(ip).digest("base64url");
}

export function resolveRequestAuditContext(request: FastifyRequest): RequestContext {
  return {
    ipHash: hashIp(request.ip),
    traceId: request.id,
    ...(typeof request.headers["user-agent"] === "string"
      ? { userAgent: request.headers["user-agent"] }
      : {})
  };
}
