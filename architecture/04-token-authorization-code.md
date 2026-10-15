# Token request: authorization code grant (POST /token)

Client authentication and redeeming the code run in parallel as subtasks of a `StructuredTaskScope`, each on its own virtual thread. If one subtask fails, the other is cancelled and its exception is rethrown by `Subtasks.join`. The code is consumed with `GETDEL` before any check, so a failed attempt cannot be retried. Client authentication is detailed in [03-client-authentication.md](03-client-authentication.md).

```mermaid
sequenceDiagram
    autonumber
    participant App as Client app
    participant TC as TokenController
    participant TS as TokenService
    participant CA as ClientAuthenticator
    participant CoR as AuthorizationCodeRepository
    participant SG as TokenSigner
    participant TR as TokenRepository
    participant R as Redis

    App->>TC: POST /token grant_type=authorization_code, code,<br/>redirect_uri, code_verifier + client credentials
    TC->>TC: TokenRequest.of(...)
    alt grant_type missing
        TC--xApp: 400 invalid_request "grant_type is required"
    else grant_type not supported
        TC--xApp: 400 unsupported_grant_type
    else code, redirect_uri or code_verifier missing
        TC--xApp: 400 invalid_request "name is required"
    end
    TC->>TC: ClientCredentials.from(...)
    Note right of TC: may fail with invalid_client / invalid_request
    TC->>TS: token(AuthorizationCodeGrant, credentials)

    par subtask 1
        TS->>CA: authenticate(credentials)
        CA-->>TS: ClientRegistration
    and subtask 2
        TS->>CoR: take(code)
        CoR->>R: GETDEL code:{code}
        R-->>CoR: AuthorizationCode or nil
        CoR-->>TS: Optional
    end
    TS->>TS: Subtasks.join(scope)
    break client authentication failed
        TS--xApp: 401 invalid_client (other subtask cancelled)
    end

    alt code unknown, expired or already used
        TS--xApp: 400 invalid_grant "Authorization code is invalid or expired"
    else code issued to another client
        TS--xApp: 400 invalid_grant "Authorization code was issued to another client"
    else redirect_uri differs from the authorization request
        TS--xApp: 400 invalid_grant "redirect_uri does not match the authorization request"
    else verifier malformed or BASE64URL(SHA256(verifier)) != challenge
        TS--xApp: 400 invalid_grant "code_verifier does not match the code_challenge"
    else all checks pass
        TS->>SG: accessToken(client, user, scope)
        SG-->>TS: SignedAccessToken(JWT typ at+jwt, jti, exp)
        par
            TS->>TR: saveAccessToken(jti, record)
            TR->>R: SET at:{jti} JSON EX 15 min
        and
            TS->>TR: saveRefreshToken(record)
            TR->>R: SET rt:{sha256(token)} JSON EX 30 days
            TR-->>TS: opaque refresh token
        and only if scope contains openid
            TS->>SG: idToken(client, user, nonce, auth_time, access token)
            SG-->>TS: ID token (aud client, at_hash)
        end
        TS-->>TC: TokenResponse
        TC-->>App: 200 access_token, token_type Bearer, expires_in,<br/>refresh_token, id_token, scope (Cache-Control: no-store)
    end
```
