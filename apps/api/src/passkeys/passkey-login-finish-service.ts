import {
  type AuthenticationResponseJSON,
  type Uint8Array_,
  type VerifiedAuthenticationResponse,
  verifyAuthenticationResponse
} from "@simplewebauthn/server";
import type { PasskeyCredential, RequestContext, User, UserId } from "../domain/identity.js";
import { isPasskeyActive } from "../domain/identity.js";
import type { ChallengeRecord, ChallengeStore, IdentityStore } from "../domain/storage.js";
import type { CreatedSession, SessionService } from "../sessions/session-service.js";

export type PasskeyLoginFinishConfig = {
  rpId: string;
  origin: string;
};

export type FinishPasskeyLoginInput = {
  loginId: string;
  credential: AuthenticationResponseJSON;
  deviceLabel?: string | null;
  context?: RequestContext;
};

export type FinishPasskeyLoginResult = {
  userId: UserId;
  credential: PasskeyCredential;
  session: CreatedSession;
};

export type PasskeyLoginFinishService = {
  finish(input: FinishPasskeyLoginInput): Promise<FinishPasskeyLoginResult>;
};

export type VerifyAuthenticationResponse = typeof verifyAuthenticationResponse;

export type PasskeyLoginFinishServiceOptions = {
  now?: () => Date;
  verifyAuthentication?: VerifyAuthenticationResponse;
};

type LoginChallengePayload = {
  challenge: string;
  rpId: string;
  origin: string;
  userId: UserId | null;
};

function assertActiveUser(user: User | null): asserts user is User {
  if (!user) {
    throw new Error("User was not found");
  }

  if (user.status !== "active") {
    throw new Error("User cannot finish passkey login unless active");
  }
}

function resolveChallengePayload(record: ChallengeRecord): LoginChallengePayload {
  const { payload } = record;

  if (
    typeof payload.challenge !== "string" ||
    typeof payload.rpId !== "string" ||
    typeof payload.origin !== "string" ||
    !(payload.userId === null || typeof payload.userId === "string")
  ) {
    throw new Error("Passkey login challenge payload is invalid");
  }

  return {
    challenge: payload.challenge,
    rpId: payload.rpId,
    origin: payload.origin,
    userId: payload.userId as UserId | null
  };
}

function assertVerified(verification: VerifiedAuthenticationResponse): void {
  if (!verification.verified) {
    throw new Error("Passkey login verification failed");
  }
}

function decodePublicKey(publicKey: string): Uint8Array_ {
  return Buffer.from(publicKey, "base64url") as Uint8Array_;
}

export class DefaultPasskeyLoginFinishService implements PasskeyLoginFinishService {
  private readonly now: () => Date;
  private readonly verifyAuthentication: VerifyAuthenticationResponse;

  constructor(
    private readonly identityStore: Pick<
      IdentityStore,
      "findPasskeyByCredentialId" | "findUserById" | "updatePasskeyUsage"
    >,
    private readonly challengeStore: ChallengeStore,
    private readonly sessionService: SessionService,
    private readonly config: PasskeyLoginFinishConfig,
    options: PasskeyLoginFinishServiceOptions = {}
  ) {
    this.now = options.now ?? (() => new Date());
    this.verifyAuthentication = options.verifyAuthentication ?? verifyAuthenticationResponse;
  }

  async finish(input: FinishPasskeyLoginInput): Promise<FinishPasskeyLoginResult> {
    const challenge = await this.challengeStore.consumeChallenge(input.loginId, "passkey_login");

    if (!challenge) {
      throw new Error("Passkey login challenge was not found");
    }

    const payload = resolveChallengePayload(challenge);
    const passkey = await this.identityStore.findPasskeyByCredentialId(input.credential.id);

    if (!passkey || !isPasskeyActive(passkey)) {
      throw new Error("Passkey credential was not found");
    }

    if (payload.userId && payload.userId !== passkey.userId) {
      throw new Error("Passkey login challenge does not match credential owner");
    }

    const user = await this.identityStore.findUserById(passkey.userId);
    assertActiveUser(user);

    if (payload.rpId !== this.config.rpId || payload.origin !== this.config.origin) {
      throw new Error("Passkey login challenge does not match relying party config");
    }

    const verification = await this.verifyAuthentication({
      response: input.credential,
      expectedChallenge: payload.challenge,
      expectedOrigin: payload.origin,
      expectedRPID: payload.rpId,
      credential: {
        id: passkey.credentialId,
        publicKey: decodePublicKey(passkey.publicKey),
        counter: passkey.signCount
      },
      requireUserVerification: true
    });
    assertVerified(verification);

    await this.identityStore.updatePasskeyUsage({
      credentialId: passkey.credentialId,
      signCount: verification.authenticationInfo.newCounter,
      usedAt: this.now()
    });

    const session = await this.sessionService.create({
      userId: passkey.userId,
      deviceLabel: input.deviceLabel ?? passkey.deviceName,
      context: input.context
    });

    return {
      userId: passkey.userId,
      credential: {
        ...passkey,
        signCount: verification.authenticationInfo.newCounter,
        lastUsedAt: this.now()
      },
      session
    };
  }
}
