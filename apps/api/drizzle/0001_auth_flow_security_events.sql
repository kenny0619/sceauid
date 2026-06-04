ALTER TYPE "public"."security_event_type" ADD VALUE IF NOT EXISTS 'passkey_registration_started';--> statement-breakpoint
ALTER TYPE "public"."security_event_type" ADD VALUE IF NOT EXISTS 'passkey_registration_failed';--> statement-breakpoint
ALTER TYPE "public"."security_event_type" ADD VALUE IF NOT EXISTS 'login_started';
