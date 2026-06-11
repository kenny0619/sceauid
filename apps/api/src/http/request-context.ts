import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

export type ErrorResponseBody = {
  error: string;
  message: string;
  requestId: string;
};

const requestIdHeader = "x-request-id";

function statusCodeFor(error: unknown): number {
  return isHttpError(error) ? error.statusCode : 500;
}

function responseBodyFor(error: unknown, request: FastifyRequest): ErrorResponseBody {
  const statusCode = statusCodeFor(error);

  if (statusCode < 500) {
    return {
      error: "request_failed",
      message: error instanceof Error ? error.message : "Request failed",
      requestId: request.id
    };
  }

  return {
    error: "internal_server_error",
    message: "Unexpected server error",
    requestId: request.id
  };
}

function attachRequestId(reply: FastifyReply, requestId: string): void {
  reply.header(requestIdHeader, requestId);
}

function isHttpError(error: unknown): error is Error & { statusCode: number } {
  const candidate = error as { statusCode?: unknown };

  return (
    error instanceof Error &&
    typeof candidate.statusCode === "number" &&
    candidate.statusCode >= 400
  );
}

export async function registerRequestContext(app: FastifyInstance): Promise<void> {
  app.addHook("onRequest", async (request, reply) => {
    attachRequestId(reply, request.id);
  });

  app.setErrorHandler((error, request, reply) => {
    const statusCode = statusCodeFor(error);

    request.log.error(
      {
        error,
        requestId: request.id,
        statusCode
      },
      "Request failed"
    );

    attachRequestId(reply, request.id);
    void reply.status(statusCode).send(responseBodyFor(error, request));
  });
}
