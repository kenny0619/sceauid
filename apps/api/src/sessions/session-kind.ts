import type { Session } from "../domain/identity.js";

export type SessionKind = "recovery" | "standard";

export const recoverySessionDeviceLabel = "Recovery session";

export function sessionKind(session: Session): SessionKind {
  return session.deviceLabel === recoverySessionDeviceLabel ? "recovery" : "standard";
}

export function isRecoverySession(session: Session): boolean {
  return sessionKind(session) === "recovery";
}

export function isStandardSession(session: Session): boolean {
  return sessionKind(session) === "standard";
}
