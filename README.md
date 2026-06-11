# SceauID

SceauID is a passkey-first identity service exploring authentication lifecycle design: registration, recovery, device/session management, and audit-grade security events.

It is not trying to replace mature auth providers or frameworks on day one. The goal is to build a small, inspectable identity infrastructure project that can grow from reference implementation into something developers can actually run, integrate, and extend.

## Why This Exists

Most auth examples stop at login. Production systems need more than that: session visibility, recovery safety, passkey lifecycle management, and an audit trail that explains how an identity changed over time.

SceauID treats authentication as a lifecycle, not a form.

## Phase 0 Scope

This repository currently contains the foundation:

- monorepo layout
- API service skeleton
- SDK, CLI, and framework package placeholders
- Docker Compose for PostgreSQL and Redis
- architecture documentation
- threat model draft
- roadmap and decision records

## Planned Capabilities

- passkey signup and login
- secure server-side sessions
- active session and device management
- recovery codes and controlled recovery flows
- structured security event timeline
- SDK and framework integrations
- operational CLI
- admin/debug console

## Repository Layout

```txt
apps/
  api/       Identity API service
  web/       Demo/admin web app

packages/
  sdk/       TypeScript integration client
  cli/       Operational CLI
  express/   Express integration package
  fastify/   Fastify integration package
  nestjs/    NestJS integration package
  nextjs/    Next.js integration package

docs/
  api/
  sdk/
  architecture/
  operations/
  security/
  adr/
```

## Documentation

- [Passkey API](docs/api/passkeys.md)
- [Browser SDK](docs/sdk/browser.md)
- [Express integration](docs/sdk/express.md)
- [Fastify integration](docs/sdk/fastify.md)
- [NestJS integration](docs/sdk/nestjs.md)
- [Next.js integration](docs/sdk/nextjs.md)
- [Configuration](docs/operations/configuration.md)
- [CSRF origin guard](docs/operations/csrf-origin-guard.md)
- [Health and readiness](docs/operations/health.md)
- [Request correlation](docs/operations/request-correlation.md)
- [Security headers](docs/operations/security-headers.md)
- [Architecture overview](docs/architecture/overview.md)
- [Threat model draft](docs/security/threat-model.md)
- [Decision records](docs/adr/)

## Local Development

```bash
pnpm install
pnpm dev
```

Start infrastructure:

```bash
docker compose up -d
```

## Current Status

SceauID is in Phase 0. The public API, database schema, and passkey flows are intentionally not marked stable yet.
