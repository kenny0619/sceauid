import type {
  RequestContext,
  RiskLevel,
  SecurityEvent,
  SecurityEventOutcome,
  SecurityEventType,
  SessionId,
  UserId
} from "../domain/identity.js";
import type { IdentityStore } from "../domain/storage.js";

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
  record(input: RecordSecurityEventInput): Promise<SecurityEvent>;
  listForUser(userId: UserId, input?: ListSecurityEventsInput): Promise<SecurityEvent[]>;
};

export type ListSecurityEventsInput = {
  eventTypes?: SecurityEventType[];
  limit?: number;
};

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

export class DefaultSecurityEventService implements SecurityEventService {
  constructor(
    private readonly store: Pick<IdentityStore, "createSecurityEvent" | "listSecurityEventsForUser">
  ) {}

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

  async listForUser(userId: UserId, input: ListSecurityEventsInput = {}): Promise<SecurityEvent[]> {
    return this.store.listSecurityEventsForUser({
      userId,
      eventTypes: input.eventTypes?.length ? input.eventTypes : undefined,
      limit: normalizeLimit(input.limit)
    });
  }
}
