ALTER TYPE "public"."security_event_type" ADD VALUE IF NOT EXISTS 'recovery_codes_enrolled';--> statement-breakpoint
ALTER TYPE "public"."security_event_type" ADD VALUE IF NOT EXISTS 'recovery_code_redeemed';
