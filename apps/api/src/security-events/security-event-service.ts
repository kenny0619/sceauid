import type {
  RequestContext,
  RiskLevel,
  SecurityEvent,
  SecurityEventId,
  SecurityEventOutcome,
  SecurityEventType,
  SessionId,
  UserId
} from "../domain/identity.js";
import type { IdentityStore, SecurityEventCursor } from "../domain/storage.js";

export type RecordSecurityEventInput = {
  userId?: UserId | null;
  actorUserId?: UserId | null;
  sessionId?: SessionId | null;
  eventType: SecurityEventType;
  outcome: SecurityEventOutcome;
  riskLevel?: RiskLevel;
  metadata?: Record<string, unknown>;
  context?: RequestContext;
};

export type SecurityEventService = {
  findForUser(userId: UserId, eventId: SecurityEventId): Promise<SecurityEvent | null>;
  record(input: RecordSecurityEventInput): Promise<SecurityEvent>;
  listForUser(userId: UserId, input?: ListSecurityEventsInput): Promise<ListSecurityEventsPage>;
};

export type ListSecurityEventsInput = {
  cursor?: string;
  eventTypes?: SecurityEventType[];
  outcomes?: SecurityEventOutcome[];
  riskLevels?: RiskLevel[];
  limit?: number;
};

export type ListSecurityEventsPage = {
  events: SecurityEvent[];
  nextCursor?: string;
};

export class InvalidSecurityEventCursorError extends Error {
  constructor() {
    super("Security event cursor is invalid");
    this.name = "InvalidSecurityEventCursorError";
  }
}

const defaultListLimit = 50;
const maxListLimit = 100;

function sanitizeRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }

  return Object.fromEntries(
    Object.entries(value).filter(([, entryValue]) => entryValue !== undefined)
  );
}

function sanitizeContext(context: RequestContext | undefined): RequestContext {
  const record = sanitizeRecord(context);

  return {
    ...(typeof record.ipHash === "string" ? { ipHash: record.ipHash } : {}),
    ...(typeof record.userAgent === "string" ? { userAgent: record.userAgent } : {}),
    ...(typeof record.traceId === "string" ? { traceId: record.traceId } : {})
  };
}

function normalizeLimit(limit: number | undefined): number {
  if (limit === undefined) {
    return defaultListLimit;
  }

  if (!Number.isFinite(limit) || limit < 1) {
    return defaultListLimit;
  }

  return Math.min(Math.floor(limit), maxListLimit);
}

function encodeCursor(cursor: SecurityEventCursor): string {
  return Buffer.from(
    JSON.stringify({
      createdAt: cursor.createdAt.toISOString(),
      id: cursor.id
    })
  ).toString("base64url");
}

function decodeCursor(cursor: string | undefined): SecurityEventCursor | undefined {
  if (cursor === undefined) {
    return undefined;
  }

  try {
    const decoded = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as {
      createdAt?: unknown;
      id?: unknown;
    };

    if (typeof decoded.createdAt !== "string" || typeof decoded.id !== "string") {
      throw new InvalidSecurityEventCursorError();
    }

    const createdAt = new Date(decoded.createdAt);

    if (Number.isNaN(createdAt.getTime())) {
      throw new InvalidSecurityEventCursorError();
    }

    return {
      createdAt,
      id: decoded.id as SecurityEventCursor["id"]
    };
  } catch (error) {
    if (error instanceof InvalidSecurityEventCursorError) {
      throw error;
    }

    throw new InvalidSecurityEventCursorError();
  }
}

export class DefaultSecurityEventService implements SecurityEventService {
  constructor(
    private readonly store: Pick<
      IdentityStore,
      "createSecurityEvent" | "findSecurityEventForUser" | "listSecurityEventsForUser"
    >
  ) {}

  async findForUser(userId: UserId, eventId: SecurityEventId): Promise<SecurityEvent | null> {
    return this.store.findSecurityEventForUser(userId, eventId);
  }

  async record(input: RecordSecurityEventInput): Promise<SecurityEvent> {
    return this.store.createSecurityEvent({
      userId: input.userId ?? null,
      actorUserId: input.actorUserId ?? null,
      sessionId: input.sessionId ?? null,
      eventType: input.eventType,
      outcome: input.outcome,
      riskLevel: input.riskLevel ?? "low",
      metadata: sanitizeRecord(input.metadata),
      context: sanitizeContext(input.context)
    });
  }

  async listForUser(
    userId: UserId,
    input: ListSecurityEventsInput = {}
  ): Promise<ListSecurityEventsPage> {
    const page = await this.store.listSecurityEventsForUser({
      userId,
      cursor: decodeCursor(input.cursor),
      eventTypes: input.eventTypes?.length ? input.eventTypes : undefined,
      outcomes: input.outcomes?.length ? input.outcomes : undefined,
      riskLevels: input.riskLevels?.length ? input.riskLevels : undefined,
      limit: normalizeLimit(input.limit)
    });

    return {
      events: page.events,
      ...(page.nextCursor ? { nextCursor: encodeCursor(page.nextCursor) } : {})
    };
  }
}
