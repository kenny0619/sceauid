import {
  type RegistrationResponseJSON,
  type VerifiedRegistrationResponse,
  verifyRegistrationResponse
} from "@simplewebauthn/server";
import type { PasskeyCredential, User, UserId } from "../domain/identity.js";
import type { ChallengeRecord, ChallengeStore, IdentityStore } from "../domain/storage.js";

export type PasskeyRegistrationFinishConfig = {
  rpId: string;
  origin: string;
};

export type FinishPasskeyRegistrationInput = {
  registrationId: string;
  credential: RegistrationResponseJSON;
  deviceName?: string | null;
};

export type FinishPasskeyRegistrationResult = {
  userId: UserId;
  credential: PasskeyCredential;
};

export type PasskeyRegistrationFinishService = {
  finish(input: FinishPasskeyRegistrationInput): Promise<FinishPasskeyRegistrationResult>;
};

export type VerifyRegistrationResponse = typeof verifyRegistrationResponse;

export type PasskeyRegistrationFinishServiceOptions = {
  verifyRegistration?: VerifyRegistrationResponse;
};

type RegistrationChallengePayload = {
  challenge: string;
  userHandle: string;
  rpId: string;
  origin: string;
};

function assertActiveUser(user: User | null): asserts user is User {
  if (!user) {
    throw new Error("User was not found");
  }

  if (user.status !== "active") {
    throw new Error("User cannot register passkeys unless active");
  }
}

function resolveChallengePayload(record: ChallengeRecord): RegistrationChallengePayload {
  const { payload } = record;

  if (
    typeof payload.challenge !== "string" ||
    typeof payload.userHandle !== "string" ||
    typeof payload.rpId !== "string" ||
    typeof payload.origin !== "string"
  ) {
    throw new Error("Passkey registration challenge payload is invalid");
  }

  return {
    challenge: payload.challenge,
    userHandle: payload.userHandle,
    rpId: payload.rpId,
    origin: payload.origin
  };
}

function assertVerified(
  verification: VerifiedRegistrationResponse
): asserts verification is Extract<VerifiedRegistrationResponse, { verified: true }> {
  if (!verification.verified) {
    throw new Error("Passkey registration verification failed");
  }
}

function encodePublicKey(publicKey: Uint8Array): string {
  return Buffer.from(publicKey).toString("base64url");
}

export class DefaultPasskeyRegistrationFinishService implements PasskeyRegistrationFinishService {
  private readonly verifyRegistration: VerifyRegistrationResponse;

  constructor(
    private readonly identityStore: Pick<
      IdentityStore,
      "createPasskeyCredential" | "findPasskeyByCredentialId" | "findUserById"
    >,
    private readonly challengeStore: ChallengeStore,
    private readonly config: PasskeyRegistrationFinishConfig,
    options: PasskeyRegistrationFinishServiceOptions = {}
  ) {
    this.verifyRegistration = options.verifyRegistration ?? verifyRegistrationResponse;
  }

  async finish(input: FinishPasskeyRegistrationInput): Promise<FinishPasskeyRegistrationResult> {
    const challenge = await this.challengeStore.consumeChallenge(
      input.registrationId,
      "passkey_registration"
    );

    if (!challenge) {
      throw new Error("Passkey registration challenge was not found");
    }

    const userId = challenge.subject as UserId;
    const user = await this.identityStore.findUserById(userId);
    assertActiveUser(user);

    const payload = resolveChallengePayload(challenge);
    const verification = await this.verifyRegistration({
      response: input.credential,
      expectedChallenge: payload.challenge,
      expectedOrigin: payload.origin,
      expectedRPID: payload.rpId,
      requireUserVerification: true
    });
    assertVerified(verification);

    if (payload.rpId !== this.config.rpId || payload.origin !== this.config.origin) {
      throw new Error("Passkey registration challenge does not match relying party config");
    }

    const credentialId = verification.registrationInfo.credential.id;
    const existingCredential = await this.identityStore.findPasskeyByCredentialId(credentialId);

    if (existingCredential) {
      throw new Error("Passkey credential already exists");
    }

    const credential = await this.identityStore.createPasskeyCredential({
      userId,
      credentialId,
      publicKey: encodePublicKey(verification.registrationInfo.credential.publicKey),
      signCount: verification.registrationInfo.credential.counter,
      deviceName: input.deviceName ?? null
    });

    return { userId, credential };
  }
}
