# Contributing

SceauID is early-stage identity infrastructure. Contributions should keep the project inspectable, security-conscious, and easy to run locally.

## Development

```bash
pnpm install
pnpm typecheck
pnpm test
```

Run local infrastructure when a task needs PostgreSQL or Redis:

```bash
docker compose up -d
```

## Contribution Principles

- Keep auth, recovery, sessions, and security events as explicit domain concepts.
- Prefer small, reviewable changes with clear tests.
- Document security tradeoffs when a change affects identity, recovery, session handling, or audit data.
- Avoid adding framework or database support without a concrete integration path.

## Commit Style

Use concise imperative commit messages:

```txt
Add session revocation model
Implement passkey registration challenge
Document recovery threat model
```
