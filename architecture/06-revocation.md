# Token revocation (POST /revoke, RFC 7009)

Client authentication and the token lookup run in parallel subtasks. The hint only decides which lookup runs first. The endpoint answers 200 also when the token is unknown, expired or belongs to another client, so it reveals nothing about other clients' tokens.

```mermaid
sequenceDiagram
    autonumber
    participant App as Client app
    participant RC as RevocationController
    participant RS as RevocationService
    participant CA as ClientAuthenticator
    participant TR as TokenRepository
    participant R as Redis

    App->>RC: POST /revoke token, optional token_type_hint + client credentials
    alt token missing or blank
        RC--xApp: 400 invalid_request "token is required"
    end
    RC->>RC: ClientCredentials.from(...)
    Note right of RC: may fail with invalid_client / invalid_request
    RC->>RS: revoke(token, hint, credentials)

    par subtask 1
        RS->>CA: authenticate(credentials)
        CA-->>RS: ClientRegistration
    and subtask 2
        alt hint is refresh_token
            RS->>TR: findRefreshToken(token)
            TR->>R: GET rt:{sha256(token)}
            opt not found
                RS->>RS: parse JWT, read jti (not a JWT: no jti)
                RS->>TR: findAccessToken(jti)
                TR->>R: GET at:{jti}
            end
        else no hint or access_token
            RS->>RS: parse JWT, read jti (not a JWT: no jti)
            RS->>TR: findAccessToken(jti)
            TR->>R: GET at:{jti}
            opt not found
                RS->>TR: findRefreshToken(token)
                TR->>R: GET rt:{sha256(token)}
            end
        end
    end
    RS->>RS: Subtasks.join(scope)
    break client authentication failed
        RS--xApp: 401 invalid_client (other subtask cancelled)
    end

    alt token not found
        Note over RS: nothing to revoke
    else found, issued to another client
        Note over RS: not revoked
    else AccessToken(jti)
        RS->>TR: deleteAccessToken(jti)
        TR->>R: DEL at:{jti}
    else RefreshToken(token)
        RS->>TR: deleteRefreshToken(token)
        TR->>R: DEL rt:{sha256(token)}
    end
    RC-->>App: 200 (empty body)
```
