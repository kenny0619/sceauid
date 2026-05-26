import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import Fastify from "fastify";
import { loadConfig } from "./config.js";

const config = loadConfig();

const app = Fastify({
  logger: {
    level: config.NODE_ENV === "development" ? "info" : "warn"
  }
});

await app.register(cors, {
  origin: config.APP_ORIGIN,
  credentials: true
});

await app.register(cookie);

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
