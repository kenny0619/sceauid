import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { describe, expect, it } from "vitest";
import type { PasskeyCredential, PasskeyCredentialId, User, UserId } from "../domain/identity.js";
import type {
  ChallengePurpose,
  ChallengeRecord,
  ChallengeStore,
  CreatePasskeyCredentialInput,
  IdentityStore
} from "../domain/storage.js";
import type { SecurityEventService } from "../security-events/security-event-service.js";
import {
  DefaultPasskeyRegistrationFinishService,
  type VerifyRegistrationResponse
} from "./passkey-registration-finish-service.js";

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

function createCredential(
  input: CreatePasskeyCredentialInput,
  overrides: Partial<PasskeyCredential> = {}
): PasskeyCredential {
  return {
    id: "passkey-id" as PasskeyCredentialId,
    userId: input.userId,
    credentialId: input.credentialId,
    publicKey: input.publicKey,
    signCount: input.signCount,
    deviceName: input.deviceName ?? null,
    lastUsedAt: null,
    createdAt: now,
    revokedAt: null,
    ...overrides
  };
}

function createChallenge(overrides: Partial<ChallengeRecord> = {}): ChallengeRecord {
  return {
    id: "registration-id",
    purpose: "passkey_registration",
    subject: userId,
    payload: {
      challenge: "public-challenge",
      userHandle: "dXNlci1pZA",
      rpId: "localhost",
      origin: "http://localhost:3000"
    },
    expiresAt: new Date("2026-06-01T12:05:00.000Z"),
    ...overrides
  };
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
    user?: User | null;
    existingCredential?: PasskeyCredential | null;
  } = {}
) {
  const createdPasskeys: CreatePasskeyCredentialInput[] = [];
  const store: Pick<
    IdentityStore,
    "createPasskeyCredential" | "findPasskeyByCredentialId" | "findUserById"
  > = {
    async createPasskeyCredential(input) {
      createdPasskeys.push(input);
      return createCredential(input);
    },
    async findPasskeyByCredentialId() {
      return options.existingCredential ?? null;
    },
    async findUserById() {
      return "user" in options ? (options.user ?? null) : createUser();
    }
  };

  return { store, createdPasskeys };
}

function createCredentialResponse(overrides: Partial<RegistrationResponseJSON> = {}) {
  return {
    id: "credential-id",
    rawId: "credential-id",
    response: {
      clientDataJSON: "client-data",
      attestationObject: "attestation-object"
    },
    clientExtensionResults: {},
    type: "public-key",
    ...overrides
  } satisfies RegistrationResponseJSON;
}

function createFakeVerifyRegistration(verified = true) {
  const calls: Parameters<VerifyRegistrationResponse>[] = [];
  const verifyRegistration: VerifyRegistrationResponse = async (options) => {
    calls.push([options]);

    if (!verified) {
      return { verified: false };
    }

    return {
      verified: true,
      registrationInfo: {
        fmt: "none",
        aaguid: "00000000-0000-0000-0000-000000000000",
        credential: {
          id: "credential-id",
          publicKey: new Uint8Array([1, 2, 3]),
          counter: 7
        },
        credentialType: "public-key",
        attestationObject: new Uint8Array([4, 5, 6]),
        userVerified: true,
        credentialDeviceType: "multiDevice",
        credentialBackedUp: true,
        origin: "http://localhost:3000",
        rpID: "localhost"
      }
    };
  };

  return { verifyRegistration, calls };
}

function createFakeSecurityEvents() {
  const records: Parameters<SecurityEventService["record"]>[0][] = [];
  const service: SecurityEventService = {
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
    user?: User | null;
    existingCredential?: PasskeyCredential | null;
    verified?: boolean;
  } = {}
) {
  const challengeStore = createFakeChallengeStore(
    "challenge" in options ? (options.challenge ?? null) : createChallenge()
  );
  const identityStore = createFakeIdentityStore({
    ...("user" in options ? { user: options.user } : {}),
    ...("existingCredential" in options ? { existingCredential: options.existingCredential } : {})
  });
  const verification = createFakeVerifyRegistration(options.verified ?? true);
  const securityEvents = createFakeSecurityEvents();
  const service = new DefaultPasskeyRegistrationFinishService(
    identityStore.store,
    challengeStore.store,
    {
      rpId: "localhost",
      origin: "http://localhost:3000"
    },
    {
      verifyRegistration: verification.verifyRegistration,
      securityEvents: securityEvents.service
    }
  );

  return { service, challengeStore, identityStore, securityEvents, verification };
}

describe("DefaultPasskeyRegistrationFinishService", () => {
  it("verifies registration and persists the passkey credential", async () => {
    const { service, challengeStore, identityStore, securityEvents, verification } =
      createService();

    const result = await service.finish({
      registrationId: "registration-id",
      credential: createCredentialResponse(),
      deviceName: "MacBook"
    });

    expect(challengeStore.consumed).toEqual([
      { id: "registration-id", purpose: "passkey_registration" }
    ]);
    expect(verification.calls[0]?.[0]).toMatchObject({
      response: createCredentialResponse(),
      expectedChallenge: "public-challenge",
      expectedOrigin: "http://localhost:3000",
      expectedRPID: "localhost",
      requireUserVerification: true
    });
    expect(identityStore.createdPasskeys).toEqual([
      {
        userId,
        credentialId: "credential-id",
        publicKey: "AQID",
        signCount: 7,
        deviceName: "MacBook"
      }
    ]);
    expect(result).toMatchObject({
      userId,
      credential: {
        credentialId: "credential-id",
        publicKey: "AQID",
        signCount: 7,
        deviceName: "MacBook"
      }
    });
    expect(securityEvents.records).toEqual([
      {
        userId,
        eventType: "passkey_registered",
        outcome: "success",
        metadata: {
          credentialId: "credential-id",
          deviceName: "MacBook",
          registrationId: "registration-id"
        }
      }
    ]);
  });

  it("rejects missing challenges and failed verification", async () => {
    await expect(
      createService({ challenge: null }).service.finish({
        registrationId: "missing",
        credential: createCredentialResponse()
      })
    ).rejects.toThrow("Passkey registration challenge was not found");

    const failedVerification = createService({ verified: false });
    await expect(
      failedVerification.service.finish({
        registrationId: "registration-id",
        credential: createCredentialResponse()
      })
    ).rejects.toThrow("Passkey registration verification failed");
    expect(failedVerification.securityEvents.records).toEqual([
      {
        userId,
        eventType: "passkey_registration_failed",
        outcome: "failure",
        riskLevel: "medium",
        metadata: {
          registrationId: "registration-id",
          reason: "Passkey registration verification failed"
        }
      }
    ]);
  });

  it("rejects inactive users, malformed payloads, and duplicate credentials", async () => {
    await expect(
      createService({ user: createUser({ status: "disabled" }) }).service.finish({
        registrationId: "registration-id",
        credential: createCredentialResponse()
      })
    ).rejects.toThrow("User cannot register passkeys unless active");

    await expect(
      createService({
        challenge: createChallenge({ payload: { challenge: "public-challenge" } })
      }).service.finish({
        registrationId: "registration-id",
        credential: createCredentialResponse()
      })
    ).rejects.toThrow("Passkey registration challenge payload is invalid");

    await expect(
      createService({
        existingCredential: createCredential({
          userId,
          credentialId: "credential-id",
          publicKey: "AQID",
          signCount: 7
        })
      }).service.finish({
        registrationId: "registration-id",
        credential: createCredentialResponse()
      })
    ).rejects.toThrow("Passkey credential already exists");
  });
});
