# NestJS Integration

`@sceauid/nestjs` wraps the TypeScript SDK for NestJS services, controllers, and guards.

## Setup

```ts
import { Module } from "@nestjs/common";
import { SceauIDModule } from "@sceauid/nestjs";

@Module({
  imports: [
    SceauIDModule.register({
      baseUrl: "https://identity.example.com"
    })
  ]
})
export class AppModule {}
```

Use `apiUrl` as an alias for `baseUrl` if that naming fits an existing config module.

## Service

Inject `SceauIDService` when backend code needs access to the underlying SceauID client:

```ts
import { Injectable } from "@nestjs/common";
import { SceauIDService } from "@sceauid/nestjs";

@Injectable()
export class AccountSecurityService {
  constructor(private readonly sceauID: SceauIDService) {}

  async listRecoveryEvents() {
    return this.sceauID.getClient().recoveryEvents({ limit: 20 });
  }
}
```

## Request Sessions

For request-scoped session checks, pass the incoming request to `currentSessionFromRequest()`. The service forwards the request cookie to SceauID and returns `null` for missing or invalid sessions.

```ts
import { Controller, Get, Req, UnauthorizedException } from "@nestjs/common";
import { SceauIDService, type SceauIDRequestLike } from "@sceauid/nestjs";

@Controller("account")
export class AccountController {
  constructor(private readonly sceauID: SceauIDService) {}

  @Get("me")
  async me(@Req() request: SceauIDRequestLike) {
    const current = await this.sceauID.currentSessionFromRequest(request);

    if (!current) {
      throw new UnauthorizedException();
    }

    return current;
  }
}
```

## Guard

Use `SceauIDCurrentSessionGuard` to protect controller handlers. The guard attaches the resolved session to `request.sceauid.currentSession` and `request.sceauidCurrentSession`.

```ts
import { Controller, Get, Req, UseGuards } from "@nestjs/common";
import {
  getSceauIDCurrentSession,
  SceauIDCurrentSessionGuard,
  type SceauIDRequestWithSession
} from "@sceauid/nestjs";

@Controller("account")
export class AccountController {
  @UseGuards(SceauIDCurrentSessionGuard)
  @Get("session")
  session(@Req() request: SceauIDRequestWithSession) {
    return getSceauIDCurrentSession(request);
  }
}
```

## Custom Cookie Name

SceauID defaults to `sceauid_session`. If the API uses a different cookie name, pass it to the module:

```ts
SceauIDModule.register({
  baseUrl: "https://identity.example.com",
  sessionCookieName: "custom_session"
});
```

The module also accepts a custom `fetch` implementation for tests, proxies, or server runtimes that need request instrumentation.
