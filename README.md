# oauth2broker

An OAuth 2 / OIDC authorization server (authorization code flow with PKCE) written in Java 25 and Spring Boot 4.

## Prerequisites

- JDK 25
- Redis on `localhost:6379`

## Run

```sh
scripts/gen-keystore.sh      # once; Windows: scripts/gen-keystore.ps1
./mvnw spring-boot:run       # https://localhost:8443
```

Tests: `./mvnw verify`. Integration tests, against the running server: `./mvnw verify -DskipITs=false`.

## Seeded credentials

Loaded from `src/main/resources/seed.json` at startup.

- User: `alice` / `wonderland`
- Clients (redirect URI `http://localhost:8080/callback`, scopes `openid profile email`):
  - `web-app`: `client_secret_basic`, secret `web-app-secret`
  - `jwt-app`: `private_key_jwt` (private key in the Postman environment)
  - `spa-app`: public client

## Try it

Open in a browser and sign in as `alice`:

```
https://localhost:8443/authorize?response_type=code&client_id=web-app&redirect_uri=http://localhost:8080/callback&scope=openid%20profile&state=xyz&code_challenge=DMcv5d3_gOzv6jEO2Pq8kXRvy8VgAiH0g_vvPvakTjQ&code_challenge_method=S256
```

The browser is redirected to `http://localhost:8080/callback?code=...` (nothing listens there; copy the code from the address bar) and redeem it within 60 seconds:

```sh
curl -k -u web-app:web-app-secret https://localhost:8443/token \
  -d grant_type=authorization_code -d code=CODE \
  -d redirect_uri=http://localhost:8080/callback \
  -d code_verifier=dBjftJeZ4CVP-mJ92K1TqvXOWcE3H3iO9-wv6l0AdYYYk

curl -k https://localhost:8443/userinfo -H "Authorization: Bearer ACCESS_TOKEN"
```

A Postman collection and environment for every flow are in `postman/`. Sequence and class diagrams are in `architecture/`.

## API docs

- Swagger UI: https://localhost:8443/swagger-ui.html
- OpenAPI: https://localhost:8443/v3/api-docs (`.yaml` for YAML)
- Discovery: https://localhost:8443/.well-known/openid-configuration
