import {
  startAuthentication as startWebAuthnAuthentication,
  startRegistration as startWebAuthnRegistration
} from "@simplewebauthn/browser";

type BrowserStartRegistration = typeof startWebAuthnRegistration;
type BrowserStartAuthentication = typeof startWebAuthnAuthentication;

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

export type WebAuthnRegistrationOptions = Parameters<BrowserStartRegistration>[0]["optionsJSON"];
export type WebAuthnAuthenticationOptions =
  Parameters<BrowserStartAuthentication>[0]["optionsJSON"];
export type WebAuthnRegistrationCredential = Awaited<ReturnType<BrowserStartRegistration>>;
export type WebAuthnAuthenticationCredential = Awaited<ReturnType<BrowserStartAuthentication>>;

export type SceauIDBrowserCeremonies = {
  startAuthentication?: BrowserStartAuthentication;
  startRegistration?: BrowserStartRegistration;
};

export type SceauIDBrowserClientOptions = SceauIDClientOptions & {
  ceremonies?: SceauIDBrowserCeremonies;
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
  options: WebAuthnRegistrationOptions;
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
  options: WebAuthnAuthenticationOptions;
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

export type CurrentSessionResponse = {
  user: {
    id: string;
    displayName: string | null;
    status: "active" | "disabled" | "pending_recovery";
  };
  session: {
    id: string;
    kind: "recovery" | "standard";
    deviceLabel: string | null;
    userAgent: string | null;
    expiresAt: string;
    authenticatedAt: string;
    createdAt: string;
  };
};

export type ListedSession = {
  id: string;
  current: boolean;
  kind: "recovery" | "standard";
  deviceLabel: string | null;
  userAgent: string | null;
  expiresAt: string;
  revokedAt: string | null;
  authenticatedAt: string;
  createdAt: string;
};

export type ListSessionsResponse = {
  sessions: ListedSession[];
};

export type LogoutResponse = {
  ok: true;
};

export type ListedSecurityEvent = {
  id: string;
  userId: string | null;
  actorUserId: string | null;
  sessionId: string | null;
  eventType: string;
  outcome: "failure" | "pending" | "success";
  riskLevel: "high" | "low" | "medium";
  metadata: Record<string, unknown>;
  context: Record<string, unknown>;
  createdAt: string;
};

export type ListSecurityEventsInput = {
  cursor?: string;
  eventTypes?: string[];
  outcomes?: Array<"failure" | "pending" | "success">;
  riskLevels?: Array<"high" | "low" | "medium">;
  createdAfter?: Date | string;
  createdBefore?: Date | string;
  limit?: number;
};

export type ListRecoveryEventsInput = Omit<ListSecurityEventsInput, "eventTypes">;

export type ListSecurityEventsResponse = {
  events: ListedSecurityEvent[];
  nextCursor: string | null;
};

export type SecurityEventResponse = {
  event: ListedSecurityEvent;
};

function appendDateQueryParam(
  searchParams: URLSearchParams,
  name: string,
  value: Date | string | undefined
): void {
  if (value === undefined) {
    return;
  }

  searchParams.set(name, value instanceof Date ? value.toISOString() : value);
}

export type ListedPasskey = {
  id: string;
  credentialId: string;
  deviceName: string | null;
  signCount: number;
  lastUsedAt: string | null;
  createdAt: string;
  revokedAt: string | null;
};

export type ListPasskeysResponse = {
  passkeys: ListedPasskey[];
};

export type RecoveryCodeStatusResponse = {
  recoveryCodesConfigured: boolean;
  unusedRecoveryCodeCount: number;
};

export type EnrollRecoveryCodesResponse = RecoveryCodeStatusResponse & {
  codes: string[];
};

export type RedeemRecoveryCodeInput = {
  code: string;
  userId: string;
};

export type RedeemRecoveryCodeResponse = {
  ok: true;
  recoveryRequest: {
    id: string;
    expiresAt: string;
    riskLevel: "medium";
  };
};

export type RecoveryRequestStatusResponse = {
  recoveryRequest: {
    id: string;
    active: boolean;
    expiresAt: string;
    riskLevel: "high" | "low" | "medium";
    status: "cancelled" | "completed" | "expired" | "pending" | "verified";
  };
};

export type CompleteRecoveryRequestResponse = {
  ok: true;
  recoverySession: {
    id: string;
    token: string;
    expiresAt: string;
  };
  recoveryRequest: {
    id: string;
    completedAt: string;
    status: "completed";
  };
};

export type CancelRecoveryRequestResponse = {
  ok: true;
  recoveryRequest: {
    id: string;
    cancelledAt: string;
    status: "cancelled";
  };
};

export type StartRecoveryPasskeyRegistrationInput = {
  recoverySessionToken: string;
  userName: string;
  userDisplayName?: string | null;
};

export type BrowserPasskeyRegistrationInput = PasskeyRegistrationStartInput & {
  deviceName?: string | null;
  useAutoRegister?: boolean;
};

export type BrowserPasskeyLoginInput = PasskeyLoginStartInput & {
  deviceLabel?: string | null;
  useBrowserAutofill?: boolean;
  verifyBrowserAutofillInput?: boolean;
};

export type BrowserRecoveryPasskeyRegistrationInput = StartRecoveryPasskeyRegistrationInput & {
  deviceName?: string | null;
  useAutoRegister?: boolean;
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

  async currentSession(): Promise<CurrentSessionResponse> {
    return this.request("/v1/sessions/current");
  }

  async sessions(): Promise<ListSessionsResponse> {
    return this.request("/v1/sessions");
  }

  async logout(): Promise<LogoutResponse> {
    return this.request("/v1/sessions/current", {
      method: "DELETE"
    });
  }

  async revokeSession(sessionId: string): Promise<LogoutResponse> {
    return this.request(`/v1/sessions/${encodeURIComponent(sessionId)}`, {
      method: "DELETE"
    });
  }

  async securityEvents(input: ListSecurityEventsInput = {}): Promise<ListSecurityEventsResponse> {
    const searchParams = new URLSearchParams();

    if (input.limit !== undefined) {
      searchParams.set("limit", String(input.limit));
    }

    if (input.cursor !== undefined) {
      searchParams.set("cursor", input.cursor);
    }

    for (const eventType of input.eventTypes ?? []) {
      searchParams.append("eventType", eventType);
    }

    for (const outcome of input.outcomes ?? []) {
      searchParams.append("outcome", outcome);
    }

    for (const riskLevel of input.riskLevels ?? []) {
      searchParams.append("riskLevel", riskLevel);
    }

    appendDateQueryParam(searchParams, "createdAfter", input.createdAfter);
    appendDateQueryParam(searchParams, "createdBefore", input.createdBefore);

    const query = searchParams.toString();

    return this.request(`/v1/security-events${query ? `?${query}` : ""}`);
  }

  async securityEvent(eventId: string): Promise<SecurityEventResponse> {
    return this.request(`/v1/security-events/${encodeURIComponent(eventId)}`);
  }

  async recoveryEvents(input: ListRecoveryEventsInput = {}): Promise<ListSecurityEventsResponse> {
    const searchParams = new URLSearchParams();

    if (input.limit !== undefined) {
      searchParams.set("limit", String(input.limit));
    }

    if (input.cursor !== undefined) {
      searchParams.set("cursor", input.cursor);
    }

    for (const outcome of input.outcomes ?? []) {
      searchParams.append("outcome", outcome);
    }

    for (const riskLevel of input.riskLevels ?? []) {
      searchParams.append("riskLevel", riskLevel);
    }

    appendDateQueryParam(searchParams, "createdAfter", input.createdAfter);
    appendDateQueryParam(searchParams, "createdBefore", input.createdBefore);

    const query = searchParams.toString();

    return this.request(`/v1/recovery/events${query ? `?${query}` : ""}`);
  }

  async passkeys(): Promise<ListPasskeysResponse> {
    return this.request("/v1/passkeys");
  }

  async revokePasskey(passkeyId: string): Promise<LogoutResponse> {
    return this.request(`/v1/passkeys/${encodeURIComponent(passkeyId)}`, {
      method: "DELETE"
    });
  }

  async recoveryCodeStatus(): Promise<RecoveryCodeStatusResponse> {
    return this.request("/v1/recovery/status");
  }

  async enrollRecoveryCodes(): Promise<EnrollRecoveryCodesResponse> {
    return this.request("/v1/recovery/codes", {
      method: "POST"
    });
  }

  async redeemRecoveryCode(input: RedeemRecoveryCodeInput): Promise<RedeemRecoveryCodeResponse> {
    return this.request("/v1/recovery/codes/redeem", {
      body: input,
      method: "POST"
    });
  }

  async recoveryRequestStatus(recoveryRequestId: string): Promise<RecoveryRequestStatusResponse> {
    return this.request(`/v1/recovery/requests/${encodeURIComponent(recoveryRequestId)}`);
  }

  async completeRecoveryRequest(
    recoveryRequestId: string
  ): Promise<CompleteRecoveryRequestResponse> {
    return this.request(`/v1/recovery/requests/${encodeURIComponent(recoveryRequestId)}/complete`, {
      method: "POST"
    });
  }

  async cancelRecoveryRequest(recoveryRequestId: string): Promise<CancelRecoveryRequestResponse> {
    return this.request(`/v1/recovery/requests/${encodeURIComponent(recoveryRequestId)}`, {
      method: "DELETE"
    });
  }

  async startRecoveryPasskeyRegistration(
    input: StartRecoveryPasskeyRegistrationInput
  ): Promise<PasskeyRegistrationStartResponse> {
    return this.request("/v1/recovery/passkeys/registration/start", {
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

export class SceauIDBrowserClient extends SceauIDClient {
  private readonly startAuthenticationCeremony: BrowserStartAuthentication;
  private readonly startRegistrationCeremony: BrowserStartRegistration;

  constructor(options: SceauIDBrowserClientOptions) {
    super(options);
    this.startAuthenticationCeremony =
      options.ceremonies?.startAuthentication ?? startWebAuthnAuthentication;
    this.startRegistrationCeremony =
      options.ceremonies?.startRegistration ?? startWebAuthnRegistration;
  }

  async registerPasskey(
    input: BrowserPasskeyRegistrationInput
  ): Promise<PasskeyRegistrationFinishResponse> {
    const registration = await this.startPasskeyRegistration({
      userId: input.userId,
      userName: input.userName,
      userDisplayName: input.userDisplayName
    });
    const credential = await this.startRegistrationCeremony({
      optionsJSON: registration.options,
      useAutoRegister: input.useAutoRegister
    });

    return this.finishPasskeyRegistration({
      registrationId: registration.registrationId,
      credential: toPasskeyRegistrationCredential(credential),
      deviceName: input.deviceName
    });
  }

  async loginWithPasskey(
    input: BrowserPasskeyLoginInput = {}
  ): Promise<PasskeyLoginFinishResponse> {
    const login = await this.startPasskeyLogin({
      userId: input.userId
    });
    const credential = await this.startAuthenticationCeremony({
      optionsJSON: login.options,
      useBrowserAutofill: input.useBrowserAutofill,
      verifyBrowserAutofillInput: input.verifyBrowserAutofillInput
    });

    return this.finishPasskeyLogin({
      loginId: login.loginId,
      credential: toPasskeyLoginCredential(credential),
      deviceLabel: input.deviceLabel
    });
  }

  async registerRecoveryPasskey(
    input: BrowserRecoveryPasskeyRegistrationInput
  ): Promise<PasskeyRegistrationFinishResponse> {
    const registration = await this.startRecoveryPasskeyRegistration({
      recoverySessionToken: input.recoverySessionToken,
      userName: input.userName,
      userDisplayName: input.userDisplayName
    });
    const credential = await this.startRegistrationCeremony({
      optionsJSON: registration.options,
      useAutoRegister: input.useAutoRegister
    });

    return this.finishPasskeyRegistration({
      registrationId: registration.registrationId,
      credential: toPasskeyRegistrationCredential(credential),
      deviceName: input.deviceName
    });
  }
}

function toPasskeyRegistrationCredential(
  credential: WebAuthnRegistrationCredential
): PasskeyRegistrationCredential {
  return {
    id: credential.id,
    rawId: credential.rawId,
    response: {
      attestationObject: credential.response.attestationObject,
      authenticatorData: credential.response.authenticatorData,
      clientDataJSON: credential.response.clientDataJSON,
      publicKey: credential.response.publicKey,
      publicKeyAlgorithm: credential.response.publicKeyAlgorithm,
      transports: credential.response.transports as PasskeyAuthenticatorTransport[] | undefined
    },
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: { ...credential.clientExtensionResults },
    type: "public-key"
  };
}

function toPasskeyLoginCredential(
  credential: WebAuthnAuthenticationCredential
): PasskeyLoginCredential {
  return {
    id: credential.id,
    rawId: credential.rawId,
    response: {
      authenticatorData: credential.response.authenticatorData,
      clientDataJSON: credential.response.clientDataJSON,
      signature: credential.response.signature,
      userHandle: credential.response.userHandle
    },
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: { ...credential.clientExtensionResults },
    type: "public-key"
  };
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
