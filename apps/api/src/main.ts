import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import Fastify from "fastify";
import { createRedisChallengeStore } from "./challenges/redis-challenge-store.js";
import { loadConfig } from "./config.js";
import { createDatabaseClient } from "./db/client.js";
import { PostgresIdentityStore } from "./db/postgres-identity-store.js";
import { DefaultPasskeyLoginFinishService } from "./passkeys/passkey-login-finish-service.js";
import { DefaultPasskeyLoginStartService } from "./passkeys/passkey-login-start-service.js";
import { registerPasskeyManagementRoutes } from "./passkeys/passkey-management-routes.js";
import { DefaultPasskeyRegistrationFinishService } from "./passkeys/passkey-registration-finish-service.js";
import { DefaultPasskeyRegistrationStartService } from "./passkeys/passkey-registration-start-service.js";
import { registerPasskeyRoutes } from "./passkeys/passkey-routes.js";
import { DefaultRecoveryCodeService } from "./recovery/recovery-code-service.js";
import { registerRecoveryRoutes } from "./recovery/recovery-routes.js";
import { registerSecurityEventRoutes } from "./security-events/security-event-routes.js";
import { DefaultSecurityEventService } from "./security-events/security-event-service.js";
import { registerSessionRoutes } from "./sessions/session-routes.js";
import { DefaultSessionService } from "./sessions/session-service.js";

const config = loadConfig();
const databaseClient = createDatabaseClient(config);
const identityStore = new PostgresIdentityStore(databaseClient.db);
const challengeStore = await createRedisChallengeStore(config.REDIS_URL);
const sessionService = new DefaultSessionService(identityStore);
const securityEvents = new DefaultSecurityEventService(identityStore);
const recoveryCodes = new DefaultRecoveryCodeService(identityStore, sessionService, {
  securityEvents
});
const loginStartService = new DefaultPasskeyLoginStartService(
  identityStore,
  challengeStore.store,
  {
    rpId: config.WEBAUTHN_RP_ID,
    origin: config.APP_ORIGIN
  },
  {
    securityEvents
  }
);
const loginFinishService = new DefaultPasskeyLoginFinishService(
  identityStore,
  challengeStore.store,
  sessionService,
  {
    rpId: config.WEBAUTHN_RP_ID,
    origin: config.APP_ORIGIN
  },
  {
    securityEvents
  }
);
const registrationStartService = new DefaultPasskeyRegistrationStartService(
  identityStore,
  challengeStore.store,
  {
    rpName: config.WEBAUTHN_RP_NAME,
    rpId: config.WEBAUTHN_RP_ID,
    origin: config.APP_ORIGIN
  },
  {
    securityEvents
  }
);
const registrationFinishService = new DefaultPasskeyRegistrationFinishService(
  identityStore,
  challengeStore.store,
  {
    rpId: config.WEBAUTHN_RP_ID,
    origin: config.APP_ORIGIN
  },
  {
    securityEvents
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
  loginFinishService,
  loginStartService,
  registrationFinishService,
  registrationStartService,
  sessionCookie: {
    name: config.SESSION_COOKIE_NAME,
    sameSite: "lax",
    secure: config.NODE_ENV === "production"
  }
});
await registerPasskeyManagementRoutes(app, {
  securityEvents,
  sessionCookieName: config.SESSION_COOKIE_NAME,
  sessionService,
  store: identityStore
});
await registerSessionRoutes(app, {
  securityEvents,
  sessionCookie: {
    name: config.SESSION_COOKIE_NAME,
    sameSite: "lax",
    secure: config.NODE_ENV === "production"
  },
  sessionService,
  store: identityStore
});
await registerRecoveryRoutes(app, {
  passkeyRegistrationStartService: registrationStartService,
  recoveryCodes,
  sessionCookieName: config.SESSION_COOKIE_NAME,
  sessionService
});
await registerSecurityEventRoutes(app, {
  securityEvents,
  sessionCookieName: config.SESSION_COOKIE_NAME,
  sessionService
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
