# Architecture

Mermaid diagrams, rendered by GitHub and most Markdown viewers. Redis keys are written as `prefix:{value}`.

| Diagram | Shows |
|---|---|
| [Request pipeline](00-request-pipeline.md) | Filters, request id, error responses for every endpoint |
| [Authorization request](01-authorization-request.md) | `GET /authorize`: validation, error page or redirect, login form |
| [Sign-in](02-sign-in.md) | `POST /authorize`: password check, single-use request, code issued |
| [Client authentication](03-client-authentication.md) | `client_secret_basic`, `private_key_jwt`, `none` |
| [Token: authorization code](04-token-authorization-code.md) | Code redemption, PKCE, tokens issued in parallel |
| [Token: refresh](05-token-refresh.md) | Refresh token rotation and scope narrowing |
| [Revocation](06-revocation.md) | `POST /revoke` (RFC 7009) |
| [UserInfo](07-userinfo.md) | Access token verification, revocation check, claims by scope |
| [Discovery](08-discovery.md) | `/.well-known/openid-configuration`, `/jwks` |
| [Startup](09-startup.md) | Signing key and `seed.json` loading |
| [Class diagram](10-class-diagram.md) | Main types by package |
