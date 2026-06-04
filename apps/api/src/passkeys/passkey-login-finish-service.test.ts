import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { describe, expect, it } from "vitest";
import type {
  PasskeyCredential,
  PasskeyCredentialId,
  Session,
  SessionId,
  User,
  UserId
} from "../domain/identity.js";
import type {
  ChallengePurpose,
  ChallengeRecord,
  ChallengeStore,
  IdentityStore,
  UpdatePasskeyUsageInput
} from "../domain/storage.js";
import type { SecurityEventService } from "../security-events/security-event-service.js";
import type { CreatedSession, SessionService } from "../sessions/session-service.js";
import type { SessionToken } from "../sessions/session-token.js";
import {
  DefaultPasskeyLoginFinishService,
  type VerifyAuthenticationResponse
} from "./passkey-login-finish-service.js";

const now = new Date("2026-06-01T12:00:00.000Z");
const userId = "user-id" as UserId;

function createUser(overrides: Partial<User> = {}): User {
  return {
    id: userId,
    displayName: "Test User",
    status: "active",
    createdAt: now,
    updatedAt: now,
    ...overrides
  };
}

function createPasskey(overrides: Partial<PasskeyCredential> = {}): PasskeyCredential {
  return {
    id: "passkey-id" as PasskeyCredentialId,
    userId,
    credentialId: "credential-id",
    publicKey: "AQID",
    signCount: 7,
    deviceName: "MacBook",
    lastUsedAt: null,
    createdAt: now,
    revokedAt: null,
    ...overrides
  };
}

function createChallenge(overrides: Partial<ChallengeRecord> = {}): ChallengeRecord {
  return {
    id: "login-id",
    purpose: "passkey_login",
    subject: userId,
    payload: {
      challenge: "public-challenge",
      rpId: "localhost",
      origin: "http://localhost:3000",
      userId
    },
    expiresAt: new Date("2026-06-01T12:05:00.000Z"),
    ...overrides
  };
}

function createCredentialResponse(overrides: Partial<AuthenticationResponseJSON> = {}) {
  return {
    id: "credential-id",
    rawId: "credential-id",
    response: {
      clientDataJSON: "client-data",
      authenticatorData: "authenticator-data",
      signature: "signature"
    },
    clientExtensionResults: {},
    type: "public-key",
    ...overrides
  } satisfies AuthenticationResponseJSON;
}

function createFakeChallengeStore(record: ChallengeRecord | null = createChallenge()) {
  const consumed: Array<{ id: string; purpose: ChallengePurpose }> = [];
  let currentRecord = record;
  const store: ChallengeStore = {
    async createChallenge() {},
    async consumeChallenge(id, purpose) {
      consumed.push({ id, purpose });
      const consumedRecord = currentRecord;
      currentRecord = null;
      return consumedRecord;
    }
  };

  return { store, consumed };
}

function createFakeIdentityStore(
  options: {
    passkey?: PasskeyCredential | null;
    user?: User | null;
  } = {}
) {
  const usageUpdates: UpdatePasskeyUsageInput[] = [];
  const store: Pick<
    IdentityStore,
    "findPasskeyByCredentialId" | "findUserById" | "updatePasskeyUsage"
  > = {
    async findPasskeyByCredentialId() {
      return "passkey" in options ? (options.passkey ?? null) : createPasskey();
    },
    async findUserById() {
      return "user" in options ? (options.user ?? null) : createUser();
    },
    async updatePasskeyUsage(input) {
      usageUpdates.push(input);
    }
  };

  return { store, usageUpdates };
}

function createFakeSessionService() {
  const creates: Parameters<SessionService["create"]>[0][] = [];
  const session: Session = {
    id: "session-id" as SessionId,
    userId,
    tokenHash: "token-hash",
    deviceLabel: "MacBook",
    userAgent: "test-agent",
    ipHash: "ip-hash",
    expiresAt: new Date("2026-07-01T12:00:00.000Z"),
    revokedAt: null,
    createdAt: now
  };
  const createdSession: CreatedSession = {
    session,
    token: "session-token" as SessionToken
  };
  const service: SessionService = {
    async create(input) {
      creates.push(input);
      return createdSession;
    },
    async authenticate() {
      return null;
    },
    async listForUser() {
      return [];
    },
    async revoke() {},
    async revokeAllForUser() {}
  };

  return { service, creates, createdSession };
}

function createFakeVerifyAuthentication(verified = true) {
  const calls: Parameters<VerifyAuthenticationResponse>[] = [];
  const verifyAuthentication: VerifyAuthenticationResponse = async (options) => {
    calls.push([options]);

    return {
      verified,
      authenticationInfo: {
        credentialID: "credential-id",
        newCounter: 8,
        userVerified: true,
        credentialDeviceType: "multiDevice",
        credentialBackedUp: true,
        origin: "http://localhost:3000",
        rpID: "localhost"
      }
    };
  };

  return { verifyAuthentication, calls };
}

function createFakeSecurityEvents() {
  const records: Parameters<SecurityEventService["record"]>[0][] = [];
  const service: SecurityEventService = {
    async findForUser() {
      return null;
    },
    async record(input) {
      records.push(input);
      return undefined as never;
    },
    async listForUser() {
      return { events: [] };
    }
  };

  return { service, records };
}

function createService(
  options: {
    challenge?: ChallengeRecord | null;
    passkey?: PasskeyCredential | null;
    user?: User | null;
    verified?: boolean;
  } = {}
) {
  const challengeStore = createFakeChallengeStore(
    "challenge" in options ? (options.challenge ?? null) : createChallenge()
  );
  const identityStore = createFakeIdentityStore({
    ...("passkey" in options ? { passkey: options.passkey } : {}),
    ...("user" in options ? { user: options.user } : {})
  });
  const sessionService = createFakeSessionService();
  const verification = createFakeVerifyAuthentication(options.verified ?? true);
  const securityEvents = createFakeSecurityEvents();
  const service = new DefaultPasskeyLoginFinishService(
    identityStore.store,
    challengeStore.store,
    sessionService.service,
    {
      rpId: "localhost",
      origin: "http://localhost:3000"
    },
    {
      now: () => now,
      verifyAuthentication: verification.verifyAuthentication,
      securityEvents: securityEvents.service
    }
  );

  return { service, challengeStore, identityStore, securityEvents, sessionService, verification };
}

describe("DefaultPasskeyLoginFinishService", () => {
  it("verifies authentication, updates passkey usage, and creates a session", async () => {
    const { service, challengeStore, identityStore, securityEvents, sessionService, verification } =
      createService();

    const result = await service.finish({
      loginId: "login-id",
      credential: createCredentialResponse(),
      deviceLabel: "Safari on macOS",
      context: {
        ipHash: "ip-hash",
        userAgent: "test-agent"
      }
    });

    expect(challengeStore.consumed).toEqual([{ id: "login-id", purpose: "passkey_login" }]);
    expect(verification.calls[0]?.[0]).toMatchObject({
      response: createCredentialResponse(),
      expectedChallenge: "public-challenge",
      expectedOrigin: "http://localhost:3000",
      expectedRPID: "localhost",
      credential: {
        id: "credential-id",
        counter: 7
      },
      requireUserVerification: true
    });
    expect(Array.from(verification.calls[0]?.[0].credential.publicKey ?? [])).toEqual([1, 2, 3]);
    expect(identityStore.usageUpdates).toEqual([
      {
        credentialId: "credential-id",
        signCount: 8,
        usedAt: now
      }
    ]);
    expect(sessionService.creates).toEqual([
      {
        userId,
        deviceLabel: "Safari on macOS",
        context: {
          ipHash: "ip-hash",
          userAgent: "test-agent"
        }
      }
    ]);
    expect(result).toMatchObject({
      userId,
      credential: {
        credentialId: "credential-id",
        signCount: 8,
        lastUsedAt: now
      },
      session: sessionService.createdSession
    });
    expect(securityEvents.records).toEqual([
      {
        userId,
        sessionId: "session-id",
        eventType: "login_succeeded",
        outcome: "success",
        metadata: {
          credentialId: "credential-id",
          loginId: "login-id"
        },
        context: {
          ipHash: "ip-hash",
          userAgent: "test-agent"
        }
      }
    ]);
  });

  it("rejects missing challenges, credentials, users, and failed verification", async () => {
    await expect(
      createService({ challenge: null }).service.finish({
        loginId: "missing",
        credential: createCredentialResponse()
      })
    ).rejects.toThrow("Passkey login challenge was not found");

    await expect(
      createService({ passkey: null }).service.finish({
        loginId: "login-id",
        credential: createCredentialResponse()
      })
    ).rejects.toThrow("Passkey credential was not found");

    await expect(
      createService({ user: createUser({ status: "disabled" }) }).service.finish({
        loginId: "login-id",
        credential: createCredentialResponse()
      })
    ).rejects.toThrow("User cannot finish passkey login unless active");

    const failedVerification = createService({ verified: false });
    await expect(
      failedVerification.service.finish({
        loginId: "login-id",
        credential: createCredentialResponse()
      })
    ).rejects.toThrow("Passkey login verification failed");
    expect(failedVerification.securityEvents.records).toEqual([
      {
        userId,
        eventType: "login_failed",
        outcome: "failure",
        riskLevel: "medium",
        metadata: {
          credentialId: "credential-id",
          loginId: "login-id",
          reason: "Passkey login verification failed"
        },
        context: undefined
      }
    ]);
  });

  it("rejects mismatched scoped login challenges and malformed payloads", async () => {
    await expect(
      createService({
        challenge: createChallenge({
          payload: {
            challenge: "public-challenge",
            rpId: "localhost",
            origin: "http://localhost:3000",
            userId: "other-user-id"
          }
        })
      }).service.finish({
        loginId: "login-id",
        credential: createCredentialResponse()
      })
    ).rejects.toThrow("Passkey login challenge does not match credential owner");

    await expect(
      createService({
        challenge: createChallenge({
          payload: {
            challenge: "public-challenge"
          }
        })
      }).service.finish({
        loginId: "login-id",
        credential: createCredentialResponse()
      })
    ).rejects.toThrow("Passkey login challenge payload is invalid");
  });
});
