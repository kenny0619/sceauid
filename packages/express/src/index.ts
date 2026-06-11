import {
  type CurrentSessionResponse,
  SceauIDClient,
  type SceauIDClientOptions,
  SceauIDError,
  type SceauIDFetchInit
} from "@sceauid/sdk";
import type { NextFunction, Request, RequestHandler, Response } from "express";

type SceauIDFetch = NonNullable<SceauIDClientOptions["fetch"]>;

declare const fetch: SceauIDFetch;

const defaultSessionCookieName = "sceauid_session";

export type SceauIDExpressOptions = {
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

export type SceauIDResolvedExpressOptions = {
  baseUrl: string;
  fetch?: SceauIDClientOptions["fetch"];
  sessionCookieName: string;
  unauthorizedBody: {
    error: string;
    message: string;
  };
};

export type SceauIDExpressRequest<TRequest extends Request = Request> = TRequest & {
  sceauid?: {
    currentSession?: CurrentSessionResponse | null;
  };
  sceauidCurrentSession?: CurrentSessionResponse | null;
};

export type SceauIDExpressIntegration = {
  client: SceauIDClient;
  currentSession: RequestHandler;
  currentSessionFromRequest(request: Request): Promise<CurrentSessionResponse | null>;
  requireCurrentSession: RequestHandler;
};

export function createSceauIDOptions(
  options: SceauIDExpressOptions
): SceauIDResolvedExpressOptions {
  const baseUrl = options.baseUrl ?? options.apiUrl;

  if (!baseUrl) {
    throw new Error("SceauID Express integration requires baseUrl");
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

export function createSceauIDExpress(options: SceauIDExpressOptions): SceauIDExpressIntegration {
  const resolvedOptions = createSceauIDOptions(options);
  const client = new SceauIDClient({
    baseUrl: resolvedOptions.baseUrl,
    fetch: resolvedOptions.fetch
  });

  return {
    client,
    currentSession: createSceauIDCurrentSessionMiddleware(resolvedOptions),
    currentSessionFromRequest: (request) => currentSessionFromRequest(resolvedOptions, request),
    requireCurrentSession: requireSceauIDCurrentSession(resolvedOptions)
  };
}

export function createSceauIDCurrentSessionMiddleware(
  options: SceauIDExpressOptions | SceauIDResolvedExpressOptions
): RequestHandler {
  const resolvedOptions = resolveOptions(options);

  return async (request, _response, next) => {
    try {
      attachCurrentSession(request, await currentSessionFromRequest(resolvedOptions, request));
      next();
    } catch (error) {
      next(error);
    }
  };
}

export function requireSceauIDCurrentSession(
  options: SceauIDExpressOptions | SceauIDResolvedExpressOptions
): RequestHandler {
  const resolvedOptions = resolveOptions(options);

  return async (request, response, next) => {
    try {
      const currentSession = await currentSessionFromRequest(resolvedOptions, request);

      if (!currentSession) {
        sendUnauthorized(response, resolvedOptions);
        return;
      }

      attachCurrentSession(request, currentSession);
      next();
    } catch (error) {
      next(error);
    }
  };
}

export async function currentSessionFromRequest(
  options: SceauIDExpressOptions | SceauIDResolvedExpressOptions,
  request: Request
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
  request: Pick<Request, "cookies" | "headers">,
  sessionCookieName = defaultSessionCookieName
): string | null {
  const header = request.headers.cookie;

  if (header) {
    return header;
  }

  const cookie = readCookieValue(request.cookies, sessionCookieName);

  return cookie ? `${sessionCookieName}=${cookie}` : null;
}

export function getSceauIDCurrentSession(
  request: SceauIDExpressRequest
): CurrentSessionResponse | null {
  return request.sceauid?.currentSession ?? request.sceauidCurrentSession ?? null;
}

function resolveOptions(
  options: SceauIDExpressOptions | SceauIDResolvedExpressOptions
): SceauIDResolvedExpressOptions {
  if ("unauthorizedBody" in options && options.baseUrl) {
    return options as SceauIDResolvedExpressOptions;
  }

  return createSceauIDOptions(options);
}

function createRequestClient(
  options: SceauIDResolvedExpressOptions,
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
  request: Request,
  currentSession: CurrentSessionResponse | null
): void {
  const sceauidRequest = request as SceauIDExpressRequest;

  sceauidRequest.sceauid = {
    ...sceauidRequest.sceauid,
    currentSession
  };
  sceauidRequest.sceauidCurrentSession = currentSession;
}

function sendUnauthorized(response: Response, options: SceauIDResolvedExpressOptions): void {
  response.status(401).json(options.unauthorizedBody);
}

function readCookieValue(cookies: Request["cookies"], name: string): string | null {
  if (!cookies || typeof cookies !== "object") {
    return null;
  }

  const value = (cookies as Record<string, unknown>)[name];

  return typeof value === "string" && value ? value : null;
}
