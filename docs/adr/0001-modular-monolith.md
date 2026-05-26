# ADR 0001: Start as a Modular Monolith

## Status

Accepted

## Context

SceauID needs separate identity concerns: passkey ceremonies, sessions, recovery, risk checks, security events, SDKs, and operational tooling.

Splitting these concerns into separate deployable services too early would add operational complexity before the domain boundaries are proven.

## Decision

SceauID will start as a modular monolith with clear internal modules and one deployable API service.

## Consequences

- The project remains easy to run locally.
- Boundaries can be tested without network overhead.
- Future extraction remains possible if a module develops independent scaling or ownership needs.
- Documentation must make internal boundaries explicit so the system does not collapse into a single auth controller.
