# Architecture Overview

SceauID starts as a modular monolith. The goal is clear identity boundaries without introducing distributed-system complexity too early.

```mermaid
flowchart TB
    Client["Demo App / Product App"]
    API["SceauID API"]
    Auth["Auth Module\nPasskey ceremonies, sessions"]
    Identity["Identity Module\nUsers, passkeys, devices"]
    Recovery["Recovery Module\nCodes, requests, delays"]
    Risk["Risk Module\nRate limits, trust checks"]
    Events["Security Event Module\nAudit-grade timeline"]
    DB[("PostgreSQL")]
    Redis[("Redis")]

    Client --> API
    API --> Auth
    API --> Identity
    API --> Recovery
    API --> Events
    Auth --> Risk
    Auth --> DB
    Auth --> Redis
    Identity --> DB
    Recovery --> DB
    Recovery --> Redis
    Risk --> Redis
    Events --> DB
```

## Boundary Decisions

- PostgreSQL stores durable identity state.
- Redis stores short-lived state such as challenges and rate limits.
- Security events are product data, not only logs.
- Sessions are server-side records so they can be inspected and revoked.
- Passkey flows are primary auth flows, not optional MFA decoration.
