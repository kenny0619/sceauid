import { describe, expect, it } from "vitest";
import type { PasskeyCredential, PasskeyCredentialId, User, UserId } from "../domain/identity.js";
import type { ChallengeRecord, ChallengeStore, IdentityStore } from "../domain/storage.js";
import {
  DefaultPasskeyLoginStartService,
  type GenerateAuthenticationOptions
} from "./passkey-login-start-service.js";

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
  const calls: Parameters<GenerateAuthenticationOptions>[] = [];
  const generateOptions: GenerateAuthenticationOptions = async (options) => {
    calls.push([options]);

    return {
      challenge: "public-challenge",
      rpId: options.rpID,
      allowCredentials: options.allowCredentials?.map((credential) => ({
        ...credential,
        type: "public-key"
      })),
      timeout: options.timeout,
      userVerification: options.userVerification
    };
  };

  return { generateOptions, calls };
}

function createService(
  options: {
    user?: User | null;
    passkeys?: PasskeyCredential[];
    ttlSeconds?: number;
  } = {}
) {
  const { store: challengeStore, records } = createFakeChallengeStore();
  const { generateOptions, calls } = createFakeGenerateOptions();
  const service = new DefaultPasskeyLoginStartService(
    createFakeIdentityStore({
      ...("user" in options ? { user: options.user } : {}),
      passkeys: options.passkeys
    }),
    challengeStore,
    {
      rpId: "localhost",
      origin: "http://localhost:3000"
    },
    {
      now: () => now,
      ttlSeconds: options.ttlSeconds,
      createLoginId: () => "login-id",
      generateOptions
    }
  );

  return { service, records, calls };
}

describe("DefaultPasskeyLoginStartService", () => {
  it("generates scoped authentication options for active user passkeys", async () => {
    const { service, records, calls } = createService({
      passkeys: [
        createPasskey("active-credential"),
        createPasskey("revoked-credential", {
          revokedAt: new Date("2026-06-01T11:00:00.000Z")
        })
      ]
    });

    const result = await service.start({ userId });

    expect(result).toMatchObject({
      loginId: "login-id",
      expiresAt: new Date("2026-06-01T12:05:00.000Z"),
      options: {
        challenge: "public-challenge",
        rpId: "localhost",
        allowCredentials: [{ id: "active-credential", type: "public-key" }],
        timeout: 300_000,
        userVerification: "preferred"
      }
    });
    expect(calls[0]?.[0]).toMatchObject({
      rpID: "localhost",
      allowCredentials: [{ id: "active-credential" }],
      timeout: 300_000,
      userVerification: "preferred"
    });
    expect(records).toEqual([
      {
        id: "login-id",
        purpose: "passkey_login",
        subject: userId,
        payload: {
          challenge: "public-challenge",
          rpId: "localhost",
          origin: "http://localhost:3000",
          userId
        },
        expiresAt: new Date("2026-06-01T12:05:00.000Z")
      }
    ]);
  });

  it("generates discoverable authentication options without a user id", async () => {
    const { service, records, calls } = createService({ ttlSeconds: 60 });

    const result = await service.start();

    expect(result).toMatchObject({
      loginId: "login-id",
      expiresAt: new Date("2026-06-01T12:01:00.000Z"),
      options: {
        challenge: "public-challenge",
        rpId: "localhost",
        timeout: 60_000,
        userVerification: "preferred"
      }
    });
    expect(calls[0]?.[0]).toMatchObject({
      rpID: "localhost",
      timeout: 60_000
    });
    expect(calls[0]?.[0].allowCredentials).toBeUndefined();
    expect(records[0]).toMatchObject({
      id: "login-id",
      purpose: "passkey_login",
      subject: "discoverable",
      payload: {
        challenge: "public-challenge",
        rpId: "localhost",
        origin: "http://localhost:3000",
        userId: null
      }
    });
  });

  it("rejects missing, inactive, and passkeyless users", async () => {
    await expect(createService({ user: null }).service.start({ userId })).rejects.toThrow(
      "User was not found"
    );
    await expect(
      createService({ user: createUser({ status: "disabled" }) }).service.start({ userId })
    ).rejects.toThrow("User cannot start passkey login unless active");
    await expect(createService({ passkeys: [] }).service.start({ userId })).rejects.toThrow(
      "User has no active passkeys"
    );
    await expect(
      createService({
        passkeys: [createPasskey("revoked", { revokedAt: now })]
      }).service.start({ userId })
    ).rejects.toThrow("User has no active passkeys");
  });
});
