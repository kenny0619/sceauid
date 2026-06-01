import { describe, expect, it } from "vitest";
import type { ChallengeRecord } from "../domain/storage.js";
import { InMemoryChallengeStore } from "./in-memory-challenge-store.js";

const now = new Date("2026-06-01T12:00:00.000Z");

function createChallenge(overrides: Partial<ChallengeRecord> = {}): ChallengeRecord {
  return {
    id: "challenge-id",
    purpose: "passkey_registration",
    subject: "user-id",
    payload: {
      challenge: "public-challenge",
      userHandle: "user-handle"
    },
    expiresAt: new Date("2026-06-01T12:05:00.000Z"),
    ...overrides
  };
}

describe("InMemoryChallengeStore", () => {
  it("consumes matching active challenges once", async () => {
    const store = new InMemoryChallengeStore({ now: () => now });
    await store.createChallenge(createChallenge());

    await expect(store.consumeChallenge("challenge-id", "passkey_registration")).resolves.toEqual(
      createChallenge()
    );
    await expect(
      store.consumeChallenge("challenge-id", "passkey_registration")
    ).resolves.toBeNull();
  });

  it("rejects mismatched purposes and removes the challenge", async () => {
    const store = new InMemoryChallengeStore({ now: () => now });
    await store.createChallenge(createChallenge());

    await expect(store.consumeChallenge("challenge-id", "passkey_login")).resolves.toBeNull();
    await expect(
      store.consumeChallenge("challenge-id", "passkey_registration")
    ).resolves.toBeNull();
  });

  it("rejects expired challenges and removes them", async () => {
    const store = new InMemoryChallengeStore({ now: () => now });
    await store.createChallenge(
      createChallenge({ expiresAt: new Date("2026-06-01T11:59:59.000Z") })
    );

    await expect(
      store.consumeChallenge("challenge-id", "passkey_registration")
    ).resolves.toBeNull();
    await expect(
      store.consumeChallenge("challenge-id", "passkey_registration")
    ).resolves.toBeNull();
  });

  it("stores and returns defensive copies", async () => {
    const store = new InMemoryChallengeStore({ now: () => now });
    const challenge = createChallenge();
    await store.createChallenge(challenge);

    challenge.payload.challenge = "changed-after-create";
    const consumed = await store.consumeChallenge("challenge-id", "passkey_registration");

    expect(consumed?.payload).toEqual({
      challenge: "public-challenge",
      userHandle: "user-handle"
    });
    if (consumed) {
      consumed.payload.challenge = "changed-after-consume";
    }
    expect(challenge.payload.challenge).toBe("changed-after-create");
  });
});
