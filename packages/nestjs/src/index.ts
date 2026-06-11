import {
  type CanActivate,
  type DynamicModule,
  type ExecutionContext,
  Injectable,
  Module,
  type Provider,
  UnauthorizedException
} from "@nestjs/common";
import {
  type CurrentSessionResponse,
  SceauIDClient,
  type SceauIDClientOptions,
  SceauIDError,
  type SceauIDFetchInit
} from "@sceauid/sdk";

type SceauIDFetch = NonNullable<SceauIDClientOptions["fetch"]>;

declare const fetch: SceauIDFetch;

export const SCEAUID_MODULE_OPTIONS = Symbol("SCEAUID_MODULE_OPTIONS");
export const SCEAUID_CLIENT = Symbol("SCEAUID_CLIENT");

const defaultSessionCookieName = "sceauid_session";

export type SceauIDNestModuleOptions = {
  apiUrl?: string;
  baseUrl?: string;
  cookieName?: string;
  fetch?: SceauIDClientOptions["fetch"];
  global?: boolean;
  sessionCookieName?: string;
};

export type SceauIDResolvedNestModuleOptions = {
  baseUrl: string;
  fetch?: SceauIDClientOptions["fetch"];
  sessionCookieName: string;
};

export type SceauIDRequestLike = {
  cookies?: Record<string, string | undefined>;
  headers?: Record<string, string | string[] | undefined>;
};

export type SceauIDRequestWithSession<TRequest extends SceauIDRequestLike = SceauIDRequestLike> =
  TRequest & {
    sceauid?: {
      currentSession?: CurrentSessionResponse;
    };
    sceauidCurrentSession?: CurrentSessionResponse;
  };

export function createSceauIDOptions(
  options: SceauIDNestModuleOptions
): SceauIDResolvedNestModuleOptions {
  const baseUrl = options.baseUrl ?? options.apiUrl;

  if (!baseUrl) {
    throw new Error("SceauID NestJS module requires baseUrl");
  }

  return {
    baseUrl,
    fetch: options.fetch,
    sessionCookieName: options.sessionCookieName ?? options.cookieName ?? defaultSessionCookieName
  };
}

export function resolveSceauIDCookieHeader(
  request: SceauIDRequestLike,
  sessionCookieName = defaultSessionCookieName
): string | null {
  const header = readHeader(request.headers, "cookie");

  if (header) {
    return header;
  }

  const cookie = request.cookies?.[sessionCookieName];

  return cookie ? `${sessionCookieName}=${cookie}` : null;
}

export function getSceauIDCurrentSession(
  request: SceauIDRequestWithSession
): CurrentSessionResponse | null {
  return request.sceauid?.currentSession ?? request.sceauidCurrentSession ?? null;
}

@Injectable()
export class SceauIDService {
  constructor(
    private readonly options: SceauIDResolvedNestModuleOptions,
    private readonly client: SceauIDClient
  ) {}

  getClient(): SceauIDClient {
    return this.client;
  }

  currentSession(): Promise<CurrentSessionResponse> {
    return this.client.currentSession();
  }

  async currentSessionFromRequest(
    request: SceauIDRequestLike
  ): Promise<CurrentSessionResponse | null> {
    const cookieHeader = resolveSceauIDCookieHeader(request, this.options.sessionCookieName);

    if (!cookieHeader) {
      return null;
    }

    try {
      return await this.createRequestClient(cookieHeader).currentSession();
    } catch (error) {
      if (error instanceof SceauIDError && error.status === 401) {
        return null;
      }

      throw error;
    }
  }

  private createRequestClient(cookieHeader: string): SceauIDClient {
    const fetcher = this.options.fetch ?? fetch;

    return new SceauIDClient({
      baseUrl: this.options.baseUrl,
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
}

@Injectable()
export class SceauIDCurrentSessionGuard implements CanActivate {
  constructor(private readonly sceauID: SceauIDService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<SceauIDRequestWithSession>();
    const currentSession = await this.sceauID.currentSessionFromRequest(request);

    if (!currentSession) {
      throw new UnauthorizedException("SceauID session is required");
    }

    request.sceauid = {
      ...request.sceauid,
      currentSession
    };
    request.sceauidCurrentSession = currentSession;

    return true;
  }
}

@Module({})
// biome-ignore lint/complexity/noStaticOnlyClass: NestJS modules conventionally expose static registration factories.
export class SceauIDModule {
  static register(options: SceauIDNestModuleOptions): DynamicModule {
    const resolvedOptions = createSceauIDOptions(options);
    const providers = createSceauIDProviders(resolvedOptions);

    return {
      module: SceauIDModule,
      global: options.global ?? false,
      providers,
      exports: [SceauIDService, SceauIDCurrentSessionGuard, SCEAUID_CLIENT]
    };
  }

  static forRoot(options: SceauIDNestModuleOptions): DynamicModule {
    return SceauIDModule.register(options);
  }
}

function createSceauIDProviders(options: SceauIDResolvedNestModuleOptions): Provider[] {
  return [
    {
      provide: SCEAUID_MODULE_OPTIONS,
      useValue: options
    },
    {
      provide: SCEAUID_CLIENT,
      inject: [SCEAUID_MODULE_OPTIONS],
      useFactory: (resolvedOptions: SceauIDResolvedNestModuleOptions) =>
        new SceauIDClient({
          baseUrl: resolvedOptions.baseUrl,
          fetch: resolvedOptions.fetch
        })
    },
    {
      provide: SceauIDService,
      inject: [SCEAUID_MODULE_OPTIONS, SCEAUID_CLIENT],
      useFactory: (resolvedOptions: SceauIDResolvedNestModuleOptions, client: SceauIDClient) =>
        new SceauIDService(resolvedOptions, client)
    },
    SceauIDCurrentSessionGuard
  ];
}

function readHeader(
  headers: SceauIDRequestLike["headers"] | undefined,
  name: string
): string | null {
  const value = headers?.[name] ?? headers?.[name.toLowerCase()] ?? headers?.[name.toUpperCase()];

  if (Array.isArray(value)) {
    return value.join("; ");
  }

  return value ?? null;
}
