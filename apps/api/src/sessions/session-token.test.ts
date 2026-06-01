import { describe, expect, it } from "vitest";
import { generateSessionToken, hashSessionToken } from "./session-token.js";

describe("session token utilities", () => {
  it("generates base64url tokens from at least 32 random bytes", () => {
    const token = generateSessionToken({
      randomBytes(size) {
        expect(size).toBe(32);
        return Buffer.alloc(size, 1);
      }
    });

    expect(token).toBe("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE");
  });

  it("rejects weak token byte lengths", () => {
    expect(() => generateSessionToken({ byteLength: 16 })).toThrow(
      "Session tokens must contain at least 32 random bytes"
    );
  });

  it("hashes session tokens with sha256", () => {
    expect(hashSessionToken("session-token")).toBe(
      "c101e911469c969171040b50d70543313cf968fdef5bacc780776f8fb399ab36"
    );
  });

  it("rejects empty tokens before hashing", () => {
    expect(() => hashSessionToken("")).toThrow("Session token cannot be empty");
  });
});
