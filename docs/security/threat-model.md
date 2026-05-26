# Threat Model Draft

This draft captures the initial security posture for SceauID. It will evolve as implementation details become concrete.

## In Scope

- Phishing attempts
- Credential stuffing pressure against fallback flows
- Stolen session cookies
- Compromised email inbox during recovery
- Database leakage
- WebAuthn challenge replay
- Account enumeration
- Brute-force recovery attempts
- Suspicious device or network changes

## Initial Controls

- Passkeys as primary credentials
- Short-lived one-time challenges
- Secure HTTP-only session cookies
- Server-side session revocation
- Recovery code hashing
- Generic recovery responses
- Rate limits for auth and recovery endpoints
- Fresh authentication before sensitive changes
- Structured security events for identity actions

## Open Questions

- Which recovery paths should be enabled by default?
- How strict should delayed recovery be for unknown devices?
- What metadata should be stored without creating unnecessary privacy risk?
- When should a session be rotated?
- Which events should be exportable through webhooks?
