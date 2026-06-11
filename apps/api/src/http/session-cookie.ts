export type SessionCookieOptions = {
  httpOnly?: boolean;
  name: string;
  path?: string;
  sameSite?: "lax" | "none" | "strict";
  secure?: boolean;
};

type ResolvedSessionCookieOptions = {
  httpOnly: boolean;
  path: string;
  sameSite: "lax" | "none" | "strict";
  secure: boolean;
};

type SessionCookieReply = {
  clearCookie(name: string, options: ResolvedSessionCookieOptions): unknown;
  setCookie(
    name: string,
    value: string,
    options: ResolvedSessionCookieOptions & {
      expires: Date;
    }
  ): unknown;
};

function resolveSessionCookieOptions(
  sessionCookie: SessionCookieOptions
): ResolvedSessionCookieOptions {
  return {
    httpOnly: sessionCookie.httpOnly ?? true,
    path: sessionCookie.path ?? "/",
    sameSite: sessionCookie.sameSite ?? "lax",
    secure: sessionCookie.secure ?? false
  };
}

export function clearSessionCookie(
  reply: Pick<SessionCookieReply, "clearCookie">,
  sessionCookie: SessionCookieOptions
): void {
  reply.clearCookie(sessionCookie.name, resolveSessionCookieOptions(sessionCookie));
}

export function setSessionCookie(
  reply: Pick<SessionCookieReply, "setCookie">,
  sessionCookie: SessionCookieOptions,
  token: string,
  expiresAt: Date
): void {
  reply.setCookie(sessionCookie.name, token, {
    ...resolveSessionCookieOptions(sessionCookie),
    expires: expiresAt
  });
}
