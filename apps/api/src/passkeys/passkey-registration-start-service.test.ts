import { describe, expect, it } from "vitest";
import type { PasskeyCredential, PasskeyCredentialId, User, UserId } from "../domain/identity.js";
import type { ChallengeRecord, ChallengeStore, IdentityStore } from "../domain/storage.js";
import type { SecurityEventService } from "../security-events/security-event-service.js";
import {
  DefaultPasskeyRegistrationStartService,
  type GenerateRegistrationOptions
} from "./passkey-registration-start-service.js";

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

function createPasskey(
  credentialId: string,
  overrides: Partial<PasskeyCredential> = {}
): PasskeyCredential {
  return {
    id: `${credentialId}-id` as PasskeyCredentialId,
    userId,
    credentialId,
    publicKey: "public-key",
    signCount: 1,
    deviceName: null,
    lastUsedAt: null,
    createdAt: now,
    revokedAt: null,
    ...overrides
  };
}

function createFakeIdentityStore(options: {
  user?: User | null;
  passkeys?: PasskeyCredential[];
}) {
  const store: Pick<IdentityStore, "findUserById" | "listPasskeysForUser"> = {
    async findUserById() {
      return "user" in options ? (options.user ?? null) : createUser();
    },
    async listPasskeysForUser() {
      return options.passkeys ?? [];
    }
  };

  return store;
}

function createFakeChallengeStore() {
  const records: ChallengeRecord[] = [];
  const store: ChallengeStore = {
    async createChallenge(record) {
      records.push(record);
    },
    async consumeChallenge() {
      return null;
    }
  };

  return { store, records };
}

function createFakeGenerateOptions() {
  const calls: Parameters<GenerateRegistrationOptions>[] = [];
  const generateOptions: GenerateRegistrationOptions = async (options) => {
    calls.push([options]);

    return {
      rp: {
        name: options.rpName,
        id: options.rpID
      },
      user: {
        id: "dXNlci1pZA",
        name: options.userName,
        displayName: options.userDisplayName ?? ""
      },
      challenge: "public-challenge",
      pubKeyCredParams: [],
      timeout: options.timeout,
      excludeCredentials: options.excludeCredentials?.map((credential) => ({
        ...credential,
        type: "public-key"
      })),
      authenticatorSelection: options.authenticatorSelection,
      attestation: options.attestationType
    };
  };

  return { generateOptions, calls };
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

describe("DefaultPasskeyRegistrationStartService", () => {
  it("generates registration options and stores a short-lived ceremony", async () => {
    const { store: challengeStore, records } = createFakeChallengeStore();
    const { generateOptions, calls } = createFakeGenerateOptions();
    const securityEvents = createFakeSecurityEvents();
    const service = new DefaultPasskeyRegistrationStartService(
      createFakeIdentityStore({
        passkeys: [
          createPasskey("active-credential"),
          createPasskey("revoked-credential", {
            revokedAt: new Date("2026-06-01T11:00:00.000Z")
          })
        ]
      }),
      challengeStore,
      {
        rpName: "SceauID",
        rpId: "localhost",
        origin: "http://localhost:3000"
      },
      {
        now: () => now,
        createRegistrationId: () => "registration-id",
        generateOptions,
        securityEvents: securityEvents.service
      }
    );

    const result = await service.start({
      userId,
      userName: "test@example.com"
    });

    expect(result).toMatchObject({
      registrationId: "registration-id",
      expiresAt: new Date("2026-06-01T12:05:00.000Z"),
      options: {
        challenge: "public-challenge",
        rp: {
          name: "SceauID",
          id: "localhost"
        },
        user: {
          name: "test@example.com",
          displayName: "Test User"
        }
      }
    });
    expect(calls[0]?.[0]).toMatchObject({
      rpName: "SceauID",
      rpID: "localhost",
      userName: "test@example.com",
      userDisplayName: "Test User",
      timeout: 300_000,
      attestationType: "none",
      excludeCredentials: [{ id: "active-credential" }],
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred"
      }
    });
    expect(Buffer.from(calls[0]?.[0].userID ?? []).toString("utf8")).toBe(userId);
    expect(records).toEqual([
      {
        id: "registration-id",
        purpose: "passkey_registration",
        subject: userId,
        payload: {
          challenge: "public-challenge",
          userHandle: "dXNlci1pZA",
          rpId: "localhost",
          origin: "http://localhost:3000"
        },
        expiresAt: new Date("2026-06-01T12:05:00.000Z")
      }
    ]);
    expect(securityEvents.records).toEqual([
      {
        userId,
        eventType: "passkey_registration_started",
        outcome: "pending",
        metadata: {
          registrationId: "registration-id",
          existingActivePasskeys: 1
        }
      }
    ]);
  });

  it("uses explicit display names and TTL overrides", async () => {
    const { store: challengeStore } = createFakeChallengeStore();
    const { generateOptions, calls } = createFakeGenerateOptions();
    const service = new DefaultPasskeyRegistrationStartService(
      createFakeIdentityStore({ user: createUser({ displayName: null }) }),
      challengeStore,
      {
        rpName: "SceauID",
        rpId: "localhost",
        origin: "http://localhost:3000"
      },
      {
        now: () => now,
        ttlSeconds: 60,
        generateOptions
      }
    );

    await service.start({
      userId,
      userName: "test@example.com",
      userDisplayName: "Preferred Name"
    });

    expect(calls[0]?.[0]).toMatchObject({
      userDisplayName: "Preferred Name",
      timeout: 60_000
    });
  });

  it("rejects missing and inactive users", async () => {
    const { store: challengeStore } = createFakeChallengeStore();
    const { generateOptions } = createFakeGenerateOptions();

    const createService = (user: User | null) =>
      new DefaultPasskeyRegistrationStartService(
        createFakeIdentityStore({ user }),
        challengeStore,
        {
          rpName: "SceauID",
          rpId: "localhost",
          origin: "http://localhost:3000"
        },
        { generateOptions }
      );

    await expect(
      createService(null).start({
        userId,
        userName: "test@example.com"
      })
    ).rejects.toThrow("User was not found");
    await expect(
      createService(createUser({ status: "disabled" })).start({
        userId,
        userName: "test@example.com"
      })
    ).rejects.toThrow("User cannot register passkeys unless active");
  });
});
