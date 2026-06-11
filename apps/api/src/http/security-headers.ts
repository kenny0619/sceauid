import type { FastifyInstance } from "fastify";

const securityHeaders = {
  "cache-control": "no-store",
  "cross-origin-opener-policy": "same-origin",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY"
} as const;

export async function registerSecurityHeaders(app: FastifyInstance): Promise<void> {
  app.addHook("onSend", async (_request, reply, payload) => {
    for (const [name, value] of Object.entries(securityHeaders)) {
      reply.header(name, value);
    }

    return payload;
  });
}
