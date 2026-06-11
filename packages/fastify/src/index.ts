import {
  type CurrentSessionResponse,
  SceauIDClient,
  type SceauIDClientOptions,
  SceauIDError,
  type SceauIDFetchInit
} from "@sceauid/sdk";
import type {
  FastifyInstance,
  FastifyPluginAsync,
  FastifyReply,
  FastifyRequest,
  preHandlerAsyncHookHandler
} from "fastify";
import fp from "fastify-plugin";

type SceauIDFetch = NonNullable<SceauIDClientOptions["fetch"]>;

declare const fetch: SceauIDFetch;

const defaultSessionCookieName = "sceauid_session";

export type SceauIDFastifyOptions = {
  apiUrl?: string;
  baseUrl?: string;
  cookieName?: string;
  fetch?: SceauIDClientOptions["fetch"];
  sessionCookieName?: string;
  unauthorizedBody?: {
    error: string;
    message: string;
  };
};

export type SceauIDResolvedFastifyOptions = {
  baseUrl: string;
  fetch?: SceauIDClientOptions["fetch"];
  sessionCookieName: string;
  unauthorizedBody: {
    error: string;
    message: string;
  };
};

export type SceauIDFastifyIntegration = {
  client: SceauIDClient;
  currentSession: preHandlerAsyncHookHandler;
  currentSessionFromRequest(request: FastifyRequest): Promise<CurrentSessionResponse | null>;
  requireCurrentSession: preHandlerAsyncHookHandler;
};

type SceauIDFastifyRequestLike = {
  cookies?: Record<string, string | undefined>;
  headers: FastifyRequest["headers"];
};

declare module "fastify" {
  interface FastifyInstance {
    sceauid: SceauIDFastifyIntegration;
  }

  interface FastifyRequest {
    sceauid?: {
      currentSession?: CurrentSessionResponse | null;
    } | null;
    sceauidCurrentSession?: CurrentSessionResponse | null;
  }
}

export function createSceauIDOptions(
  options: SceauIDFastifyOptions
): SceauIDResolvedFastifyOptions {
  const baseUrl = options.baseUrl ?? options.apiUrl;

  if (!baseUrl) {
    throw new Error("SceauID Fastify plugin requires baseUrl");
  }

  return {
    baseUrl,
    fetch: options.fetch,
    sessionCookieName: options.sessionCookieName ?? options.cookieName ?? defaultSessionCookieName,
    unauthorizedBody: options.unauthorizedBody ?? {
      error: "unauthenticated",
      message: "SceauID session is required"
    }
  };
}

export function sceauidFastify(options: SceauIDFastifyOptions): FastifyPluginAsync {
  const integration = createSceauIDFastify(options);

  return fp(
    async (app) => {
      app.decorate("sceauid", integration);
      app.decorateRequest("sceauid", null);
      app.decorateRequest("sceauidCurrentSession", null);
    },
    {
      name: "@sceauid/fastify"
    }
  );
}

export function createSceauIDFastify(options: SceauIDFastifyOptions): SceauIDFastifyIntegration {
  const resolvedOptions = createSceauIDOptions(options);
  const client = new SceauIDClient({
    baseUrl: resolvedOptions.baseUrl,
    fetch: resolvedOptions.fetch
  });

  return {
    client,
    currentSession: createSceauIDCurrentSessionPreHandler(resolvedOptions),
    currentSessionFromRequest: (request) => currentSessionFromRequest(resolvedOptions, request),
    requireCurrentSession: requireSceauIDCurrentSession(resolvedOptions)
  };
}

export function createSceauIDCurrentSessionPreHandler(
  options: SceauIDFastifyOptions | SceauIDResolvedFastifyOptions
): preHandlerAsyncHookHandler {
  const resolvedOptions = resolveOptions(options);

  return async (request) => {
    attachCurrentSession(request, await currentSessionFromRequest(resolvedOptions, request));
  };
}

export function requireSceauIDCurrentSession(
  options: SceauIDFastifyOptions | SceauIDResolvedFastifyOptions
): preHandlerAsyncHookHandler {
  const resolvedOptions = resolveOptions(options);

  return async (request, reply) => {
    const currentSession = await currentSessionFromRequest(resolvedOptions, request);

    if (!currentSession) {
      await sendUnauthorized(reply, resolvedOptions);
      return;
    }

    attachCurrentSession(request, currentSession);
  };
}

export async function currentSessionFromRequest(
  options: SceauIDFastifyOptions | SceauIDResolvedFastifyOptions,
  request: FastifyRequest
): Promise<CurrentSessionResponse | null> {
  const resolvedOptions = resolveOptions(options);
  const cookieHeader = resolveSceauIDCookieHeader(request, resolvedOptions.sessionCookieName);

  if (!cookieHeader) {
    return null;
  }

  try {
    return await createRequestClient(resolvedOptions, cookieHeader).currentSession();
  } catch (error) {
    if (error instanceof SceauIDError && error.status === 401) {
      return null;
    }

    throw error;
  }
}

export function resolveSceauIDCookieHeader(
  request: SceauIDFastifyRequestLike,
  sessionCookieName = defaultSessionCookieName
): string | null {
  const header = request.headers.cookie;

  if (Array.isArray(header)) {
    return header.join("; ");
  }

  if (header) {
    return header;
  }

  const cookie = readCookieValue(request.cookies, sessionCookieName);

  return cookie ? `${sessionCookieName}=${cookie}` : null;
}

export function getSceauIDCurrentSession(request: FastifyRequest): CurrentSessionResponse | null {
  return request.sceauid?.currentSession ?? request.sceauidCurrentSession ?? null;
}

function resolveOptions(
  options: SceauIDFastifyOptions | SceauIDResolvedFastifyOptions
): SceauIDResolvedFastifyOptions {
  if ("unauthorizedBody" in options && options.baseUrl) {
    return options as SceauIDResolvedFastifyOptions;
  }

  return createSceauIDOptions(options);
}

function createRequestClient(
  options: SceauIDResolvedFastifyOptions,
  cookieHeader: string
): SceauIDClient {
  const fetcher = options.fetch ?? fetch;

  return new SceauIDClient({
    baseUrl: options.baseUrl,
    fetch: async (url, init) =>
      fetcher(url, {
        ...init,
        headers: {
          ...init?.headers,
          Cookie: cookieHeader
        } satisfies SceauIDFetchInit["headers"]
      })
  });
}

function attachCurrentSession(
  request: FastifyRequest,
  currentSession: CurrentSessionResponse | null
): void {
  request.sceauid = {
    ...request.sceauid,
    currentSession
  };
  request.sceauidCurrentSession = currentSession;
}

async function sendUnauthorized(
  reply: FastifyReply,
  options: SceauIDResolvedFastifyOptions
): Promise<void> {
  await reply.status(401).send(options.unauthorizedBody);
}

function readCookieValue(
  cookies: SceauIDFastifyRequestLike["cookies"],
  name: string
): string | null {
  if (!cookies || typeof cookies !== "object") {
    return null;
  }

  const value = (cookies as Record<string, unknown>)[name];

  return typeof value === "string" && value ? value : null;
}
