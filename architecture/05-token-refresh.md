# Token request: refresh token grant (POST /token)

The refresh token is rotated: the old one is deleted with `GETDEL` and a new one with the originally granted scope is issued. Of two concurrent requests with the same token, only one wins. Validation of `grant_type` and client credentials in the controller is the same as in [04-token-authorization-code.md](04-token-authorization-code.md).

```mermaid
sequenceDiagram
    autonumber
    participant App as Client app
    participant TC as TokenController
    participant TS as TokenService
    participant CA as ClientAuthenticator
    participant SG as TokenSigner
    participant TR as TokenRepository
    participant R as Redis

    App->>TC: POST /token grant_type=refresh_token, refresh_token,<br/>optional scope + client credentials
    alt refresh_token missing
        TC--xApp: 400 invalid_request "refresh_token is required"
    end
    TC->>TS: token(RefreshTokenGrant, credentials)

    par subtask 1
        TS->>CA: authenticate(credentials)
        CA-->>TS: ClientRegistration
    and subtask 2
        TS->>TR: findRefreshToken(token)
        TR->>R: GET rt:{sha256(token)}
        R-->>TR: RefreshTokenRecord or nil
    end
    TS->>TS: Subtasks.join(scope)
    break client authentication failed
        TS--xApp: 401 invalid_client (other subtask cancelled)
    end

    alt token unknown, expired or revoked
        TS--xApp: 400 invalid_grant "Refresh token is invalid or expired"
    else token issued to another client
        TS--xApp: 400 invalid_grant "Refresh token was issued to another client"
    else requested scope not within the granted scope
        TS--xApp: 400 invalid_scope "scope exceeds the originally granted scope"
    else checks pass
        TS->>TR: takeRefreshToken(token)
        TR->>R: GETDEL rt:{sha256(token)}
        alt a concurrent request already rotated it
            R-->>TR: nil
            TS--xApp: 400 invalid_grant "Refresh token is invalid or expired"
        else rotated
            R-->>TR: RefreshTokenRecord
            TS->>SG: accessToken(client, user, requested scope)
            SG-->>TS: SignedAccessToken
            par
                TS->>TR: saveAccessToken(jti, record)
                TR->>R: SET at:{jti} JSON EX 15 min
            and
                TS->>TR: saveRefreshToken(record with granted scope)
                TR->>R: SET rt:{sha256(new token)} JSON EX 30 days
            end
            TS-->>TC: TokenResponse (no id_token)
            TC-->>App: 200 access_token, new refresh_token, scope
        end
    end
```
