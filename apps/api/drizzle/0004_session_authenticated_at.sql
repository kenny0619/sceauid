ALTER TABLE "sessions" ADD COLUMN "authenticated_at" timestamp with time zone;
--> statement-breakpoint
UPDATE "sessions" SET "authenticated_at" = "created_at" WHERE "authenticated_at" IS NULL;
--> statement-breakpoint
ALTER TABLE "sessions" ALTER COLUMN "authenticated_at" SET NOT NULL;
--> statement-breakpoint
ALTER TABLE "sessions" ALTER COLUMN "authenticated_at" SET DEFAULT now();
