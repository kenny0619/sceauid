import {
  type CurrentSessionResponse,
  SceauIDClient,
  type SceauIDClientOptions,
  SceauIDError,
  type SceauIDFetchInit
} from "@sceauid/sdk";

type SceauIDFetch = NonNullable<SceauIDClientOptions["fetch"]>;

declare const fetch: SceauIDFetch;

const defaultSessionCookieName = "sceauid_session";

export type SceauIDNextOptions = {
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

export type SceauIDResolvedNextOptions = {
  baseUrl: string;
  fetch?: SceauIDClientOptions["fetch"];
  sessionCookieName: string;
  unauthorizedBody: {
    error: string;
    message: string;
  };
};

export type SceauIDCookieStore = {
  get(name: string): { value: string } | undefined;
};

export type SceauIDCookieStoreInput = Promise<SceauIDCookieStore> | SceauIDCookieStore;

export type SceauIDNextRequest = Request & {
  nextUrl?: URL;
};

export type SceauIDMiddlewareOptions = SceauIDNextOptions & {
  loginPath?: string;
  publicPaths?: Array<RegExp | string>;
  redirectToLogin?: boolean;
};

export type SceauIDNextIntegration = {
  client: SceauIDClient;
  currentSessionFromCookieHeader(
    cookieHeader: string | null
  ): Promise<CurrentSessionResponse | null>;
  currentSessionFromCookies(
    cookieStore: SceauIDCookieStoreInput
  ): Promise<CurrentSessionResponse | null>;
  currentSessionFromRequest(request: SceauIDNextRequest): Promise<CurrentSessionResponse | null>;
  middleware(
    options?: Omit<SceauIDMiddlewareOptions, keyof SceauIDNextOptions>
  ): (request: SceauIDNextRequest) => Promise<Response | undefined>;
  unauthorizedResponse(): Response;
};

export function createSceauIDOptions(options: SceauIDNextOptions): SceauIDResolvedNextOptions {
  const baseUrl = options.baseUrl ?? options.apiUrl;

  if (!baseUrl) {
    throw new Error("SceauID Next.js integration requires baseUrl");
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

export function createSceauIDNext(options: SceauIDNextOptions): SceauIDNextIntegration {
  const resolvedOptions = createSceauIDOptions(options);
  const client = new SceauIDClient({
    baseUrl: resolvedOptions.baseUrl,
    fetch: resolvedOptions.fetch
  });

  return {
    client,
    currentSessionFromCookieHeader: (cookieHeader) =>
      currentSessionFromCookieHeader(resolvedOptions, cookieHeader),
    currentSessionFromCookies: (cookieStore) =>
      currentSessionFromCookies(resolvedOptions, cookieStore),
    currentSessionFromRequest: (request) => currentSessionFromRequest(resolvedOptions, request),
    middleware: (middlewareOptions) =>
      createSceauIDMiddleware({
        ...options,
        ...middlewareOptions
      }),
    unauthorizedResponse: () => unauthorizedResponse(resolvedOptions)
  };
}

export async function currentSessionFromRequest(
  options: SceauIDNextOptions | SceauIDResolvedNextOptions,
  request: SceauIDNextRequest
): Promise<CurrentSessionResponse | null> {
  return currentSessionFromCookieHeader(resolveOptions(options), request.headers.get("cookie"));
}

export async function currentSessionFromCookies(
  options: SceauIDNextOptions | SceauIDResolvedNextOptions,
  cookieStore: SceauIDCookieStoreInput
): Promise<CurrentSessionResponse | null> {
  const resolvedOptions = resolveOptions(options);
  const cookie = (await cookieStore).get(resolvedOptions.sessionCookieName)?.value;

  return currentSessionFromCookieHeader(
    resolvedOptions,
    cookie ? `${resolvedOptions.sessionCookieName}=${cookie}` : null
  );
}

export async function currentSessionFromCookieHeader(
  options: SceauIDNextOptions | SceauIDResolvedNextOptions,
  cookieHeader: string | null
): Promise<CurrentSessionResponse | null> {
  const resolvedOptions = resolveOptions(options);

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

export function createSceauIDMiddleware(
  options: SceauIDMiddlewareOptions
): (request: SceauIDNextRequest) => Promise<Response | undefined> {
  const resolvedOptions = createSceauIDOptions(options);

  return async (request) => {
    const requestUrl = getRequestUrl(request);

    if (isPublicPath(requestUrl.pathname, options.publicPaths ?? [])) {
      return undefined;
    }

    const currentSession = await currentSessionFromRequest(resolvedOptions, request);

    if (currentSession) {
      return undefined;
    }

    if (options.redirectToLogin && options.loginPath) {
      return redirectToLogin(requestUrl, options.loginPath);
    }

    return unauthorizedResponse(resolvedOptions);
  };
}

export function unauthorizedResponse(
  options: SceauIDNextOptions | SceauIDResolvedNextOptions
): Response {
  const resolvedOptions = resolveOptions(options);

  return Response.json(resolvedOptions.unauthorizedBody, { status: 401 });
}

function resolveOptions(
  options: SceauIDNextOptions | SceauIDResolvedNextOptions
): SceauIDResolvedNextOptions {
  if ("unauthorizedBody" in options && options.baseUrl) {
    return options as SceauIDResolvedNextOptions;
  }

  return createSceauIDOptions(options);
}

function createRequestClient(
  options: SceauIDResolvedNextOptions,
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

function isPublicPath(pathname: string, publicPaths: Array<RegExp | string>): boolean {
  return publicPaths.some((publicPath) => {
    if (publicPath instanceof RegExp) {
      return publicPath.test(pathname);
    }

    return pathname === publicPath || pathname.startsWith(`${publicPath}/`);
  });
}

function getRequestUrl(request: SceauIDNextRequest): URL {
  return request.nextUrl ? new URL(request.nextUrl) : new URL(request.url);
}

function redirectToLogin(requestUrl: URL, loginPath: string): Response {
  const url = new URL(requestUrl);
  url.pathname = loginPath;
  url.search = "";
  url.searchParams.set("next", `${requestUrl.pathname}${requestUrl.search}`);

  return Response.redirect(url, 307);
}
