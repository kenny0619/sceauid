import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import Fastify from "fastify";
import { createRedisChallengeStore } from "./challenges/redis-challenge-store.js";
import { loadConfig } from "./config.js";
import { createDatabaseClient } from "./db/client.js";
import { PostgresIdentityStore } from "./db/postgres-identity-store.js";
import { DefaultPasskeyLoginStartService } from "./passkeys/passkey-login-start-service.js";
import { DefaultPasskeyRegistrationFinishService } from "./passkeys/passkey-registration-finish-service.js";
import { DefaultPasskeyRegistrationStartService } from "./passkeys/passkey-registration-start-service.js";
import { registerPasskeyRoutes } from "./passkeys/passkey-routes.js";

const config = loadConfig();
const databaseClient = createDatabaseClient(config);
const identityStore = new PostgresIdentityStore(databaseClient.db);
const challengeStore = await createRedisChallengeStore(config.REDIS_URL);
const loginStartService = new DefaultPasskeyLoginStartService(identityStore, challengeStore.store, {
  rpId: config.WEBAUTHN_RP_ID,
  origin: config.APP_ORIGIN
});
const registrationStartService = new DefaultPasskeyRegistrationStartService(
  identityStore,
  challengeStore.store,
  {
    rpName: config.WEBAUTHN_RP_NAME,
    rpId: config.WEBAUTHN_RP_ID,
    origin: config.APP_ORIGIN
  }
);
const registrationFinishService = new DefaultPasskeyRegistrationFinishService(
  identityStore,
  challengeStore.store,
  {
    rpId: config.WEBAUTHN_RP_ID,
    origin: config.APP_ORIGIN
  }
);

const app = Fastify({
  logger: {
    level: config.NODE_ENV === "development" ? "info" : "warn"
  }
});

app.addHook("onClose", async () => {
  await challengeStore.close();
  await databaseClient.close();
});

await app.register(cors, {
  origin: config.APP_ORIGIN,
  credentials: true
});

await app.register(cookie);
await registerPasskeyRoutes(app, {
  loginStartService,
  registrationFinishService,
  registrationStartService
});

app.get("/health", async () => ({
  status: "ok",
  service: "sceauid-api"
}));

app.get("/v1/meta", async () => ({
  name: "SceauID",
  phase: "0",
  capabilities: [
    "passkey-first identity",
    "server-side sessions",
    "security events",
    "controlled recovery"
  ]
}));

await app.listen({
  host: "0.0.0.0",
  port: config.PORT
});
