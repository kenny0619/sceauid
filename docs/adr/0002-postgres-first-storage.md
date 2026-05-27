# ADR 0002: Use PostgreSQL as the First Durable Store

## Status

Accepted

## Context

SceauID stores identity data with strong relationships and security-sensitive invariants:

- users own email addresses, passkeys, sessions, recovery codes, and recovery requests
- emails, passkey credential IDs, session token hashes, and recovery code hashes need uniqueness
- session and recovery state changes should be transaction-friendly
- security events need predictable ordering, filtering, and retention

The project should eventually be storage-adapter ready, but supporting multiple durable stores before the core model is stable would add abstraction without enough evidence.

## Decision

SceauID will be PostgreSQL-first for durable identity storage.

The API domain will keep storage behind interfaces so future adapters can support other databases where there is a concrete use case.

## Consequences

- The first implementation can rely on relational constraints, indexes, and migrations.
- The domain model remains decoupled from Drizzle and PostgreSQL-specific details.
- MongoDB, MySQL, or other stores can be evaluated later through adapter interfaces and compatibility tests.
- Redis remains separate as an ephemeral store for challenges, rate limits, and short-lived recovery state.
