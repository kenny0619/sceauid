CREATE INDEX IF NOT EXISTS "security_events_actor_user_id_idx" ON "security_events" ("actor_user_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "security_events_session_id_idx" ON "security_events" ("session_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "security_events_context_trace_id_idx" ON "security_events" (("context"->>'traceId'));
