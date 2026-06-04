type SceauIDFetchResponse = {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
};

export type SceauIDFetchInit = {
  body?: string;
  credentials?: "include" | "omit" | "same-origin";
  headers?: Record<string, string>;
  method?: string;
};

type SceauIDFetch = (url: string, init?: SceauIDFetchInit) => Promise<SceauIDFetchResponse>;

declare const fetch: SceauIDFetch;

export type SceauIDClientOptions = {
  baseUrl: string;
  fetch?: SceauIDFetch;
};

export type SceauIDErrorBody = {
  error?: string;
  message?: string;
};

export class SceauIDError extends Error {
  readonly code?: string;
  readonly status: number;

  constructor(status: number, body: SceauIDErrorBody = {}) {
    super(body.message ?? `SceauID request failed with status ${status}`);
    this.name = "SceauIDError";
    this.status = status;
    this.code = body.error;
  }
}

export type PasskeyAuthenticatorAttachment = "cross-platform" | "platform";

export type PasskeyAuthenticatorTransport =
  | "ble"
  | "cable"
  | "hybrid"
  | "internal"
  | "nfc"
  | "smart-card"
  | "usb";

export type PasskeyClientExtensionResults = Record<string, unknown>;

export type PasskeyRegistrationStartInput = {
  userId: string;
  userName: string;
  userDisplayName?: string | null;
};

export type PasskeyRegistrationStartResponse = {
  registrationId: string;
  expiresAt: string;
  options: unknown;
};

export type PasskeyRegistrationCredential = {
  id: string;
  rawId: string;
  response: {
    attestationObject: string;
    authenticatorData?: string;
    clientDataJSON: string;
    publicKey?: string;
    publicKeyAlgorithm?: number;
    transports?: PasskeyAuthenticatorTransport[];
  };
  authenticatorAttachment?: PasskeyAuthenticatorAttachment;
  clientExtensionResults: PasskeyClientExtensionResults;
  type: "public-key";
};

export type PasskeyRegistrationFinishInput = {
  registrationId: string;
  credential: PasskeyRegistrationCredential;
  deviceName?: string | null;
};

export type PasskeyRegistrationFinishResponse = {
  userId: string;
  credential: {
    id: string;
    credentialId: string;
    deviceName: string | null;
    createdAt: string;
  };
};

export type PasskeyLoginStartInput = {
  userId?: string;
};

export type PasskeyLoginStartResponse = {
  loginId: string;
  expiresAt: string;
  options: unknown;
};

export type PasskeyLoginCredential = {
  id: string;
  rawId: string;
  response: {
    authenticatorData: string;
    clientDataJSON: string;
    signature: string;
    userHandle?: string;
  };
  authenticatorAttachment?: PasskeyAuthenticatorAttachment;
  clientExtensionResults: PasskeyClientExtensionResults;
  type: "public-key";
};

export type PasskeyLoginFinishInput = {
  loginId: string;
  credential: PasskeyLoginCredential;
  deviceLabel?: string | null;
};

export type PasskeyLoginFinishResponse = {
  userId: string;
  credential: {
    id: string;
    credentialId: string;
    signCount: number;
    lastUsedAt: string | null;
  };
  session: {
    id: string;
    token: string;
    expiresAt: string;
  };
};

export class SceauIDClient {
  private readonly baseUrl: string;
  private readonly fetcher: SceauIDFetch;

  constructor(options: SceauIDClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.fetcher = options.fetch ?? fetch;
  }

  async startPasskeyRegistration(
    input: PasskeyRegistrationStartInput
  ): Promise<PasskeyRegistrationStartResponse> {
    return this.request("/v1/passkeys/registration/start", {
      body: input,
      method: "POST"
    });
  }

  async finishPasskeyRegistration(
    input: PasskeyRegistrationFinishInput
  ): Promise<PasskeyRegistrationFinishResponse> {
    return this.request("/v1/passkeys/registration/finish", {
      body: input,
      method: "POST"
    });
  }

  async startPasskeyLogin(input: PasskeyLoginStartInput = {}): Promise<PasskeyLoginStartResponse> {
    return this.request("/v1/passkeys/login/start", {
      body: input,
      method: "POST"
    });
  }

  async finishPasskeyLogin(input: PasskeyLoginFinishInput): Promise<PasskeyLoginFinishResponse> {
    return this.request("/v1/passkeys/login/finish", {
      body: input,
      method: "POST"
    });
  }

  async meta(): Promise<unknown> {
    return this.request("/v1/meta");
  }

  private async request<TResponse>(
    path: string,
    options: {
      body?: unknown;
      method?: string;
    } = {}
  ): Promise<TResponse> {
    const response = await this.fetcher(`${this.baseUrl}${path}`, {
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      credentials: "include",
      headers: {
        Accept: "application/json",
        ...(options.body === undefined ? {} : { "Content-Type": "application/json" })
      },
      method: options.method ?? "GET"
    });

    if (!response.ok) {
      throw new SceauIDError(response.status, await parseErrorBody(response));
    }

    return response.json() as Promise<TResponse>;
  }
}

async function parseErrorBody(response: SceauIDFetchResponse): Promise<SceauIDErrorBody> {
  try {
    const body = await response.json();

    if (body && typeof body === "object") {
      return body as SceauIDErrorBody;
    }
  } catch {
    return {};
  }

  return {};
}
