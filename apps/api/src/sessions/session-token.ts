import { createHash, randomBytes } from "node:crypto";

export type SessionToken = string & { readonly __brand: "SessionToken" };

export type GenerateSessionTokenOptions = {
  byteLength?: number;
  randomBytes?: (size: number) => Buffer;
};

const defaultTokenByteLength = 32;

export function generateSessionToken(options: GenerateSessionTokenOptions = {}): SessionToken {
  const byteLength = options.byteLength ?? defaultTokenByteLength;

  if (!Number.isInteger(byteLength) || byteLength < 32) {
    throw new Error("Session tokens must contain at least 32 random bytes");
  }

  const bytes = options.randomBytes?.(byteLength) ?? randomBytes(byteLength);
  return bytes.toString("base64url") as SessionToken;
}

export function hashSessionToken(token: string): string {
  if (token.length === 0) {
    throw new Error("Session token cannot be empty");
  }

  return createHash("sha256").update(token).digest("hex");
}
