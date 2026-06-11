# Security Headers

SceauID adds conservative security headers to API responses.

```txt
cache-control: no-store
cross-origin-opener-policy: same-origin
referrer-policy: no-referrer
x-content-type-options: nosniff
x-frame-options: DENY
```

## No Store

Identity responses can contain session, passkey, recovery, or audit data. `cache-control: no-store` tells browsers and shared proxies not to persist API responses.

## Content Sniffing

`x-content-type-options: nosniff` prevents clients from interpreting JSON responses as another content type.

## Referrers And Framing

`referrer-policy: no-referrer` avoids leaking API URLs through referrer headers.

`x-frame-options: DENY` prevents browsers from framing API responses.

## Cross-Origin Opener Policy

`cross-origin-opener-policy: same-origin` gives SceauID a stricter default isolation boundary for browser-handled responses.
