# Client authentication (token and revocation endpoints)

The controller picks the method from the request (`ClientCredentials.from`), then `ClientAuthenticator` checks it against the client's registered method. Every failure is an `InvalidClient` (401, `WWW-Authenticate: Basic`) except using two methods at once, which is an `InvalidRequest` (400). See [the request pipeline](00-request-pipeline.md) for how errors become responses.

## Choosing the method

```mermaid
sequenceDiagram
    autonumber
    participant CT as TokenController / RevocationController
    participant CC as ClientCredentials.from

    CT->>CC: from(Authorization header, client_id, client_assertion_type, client_assertion)
    alt Basic header and client_assertion both present
        CC--xCT: InvalidRequest "Use only one client authentication method"
    else Basic header
        alt not base64, or no colon after decoding
            CC--xCT: InvalidClient "Malformed Basic credentials"
        else
            CC-->>CT: SecretBasic(id, secret), both form-decoded
        end
    else client_assertion present
        alt client_assertion_type is not jwt-bearer
            CC--xCT: InvalidClient "client_assertion_type must be ..."
        else
            CC-->>CT: PrivateKeyJwt(client_id or null, assertion)
        end
    else only client_id
        CC-->>CT: PublicClient(client_id)
    else nothing
        CC--xCT: InvalidClient "Client authentication is required"
    end
```

## Verifying the credentials

```mermaid
sequenceDiagram
    autonumber
    participant S as TokenService / RevocationService
    participant CA as ClientAuthenticator
    participant CR as ClientRepository
    participant PE as PasswordEncoder (BCrypt)
    participant AR as AssertionReplayRepository
    participant R as Redis

    S->>CA: authenticate(credentials)
    CA->>CR: find(client_id)
    CR->>R: GET client:{client_id}
    R-->>CR: ClientRegistration or nil
    Note over CA: registered(): an unknown client, or one registered<br/>for another method, fails with InvalidClient<br/>"Client authentication failed"

    alt SecretBasic
        CA->>PE: matches(secret, clientSecretHash)
        alt secret does not match
            CA--xS: InvalidClient "Client authentication failed"
        else
            CA-->>S: ClientRegistration
        end
    else PrivateKeyJwt (RFC 7523)
        CA->>CA: SignedJWT.parse(assertion)
        alt cannot parse
            CA--xS: InvalidClient "Malformed client assertion"
        else iss missing, iss != sub, or iss != client_id parameter
            CA--xS: InvalidClient "Assertion iss and sub must be the client_id"
        else alg not RS256 or ES256
            CA--xS: InvalidClient "Assertion must be signed with RS256 or ES256"
        else no registered JWK (matching kid and key type) verifies the signature
            CA--xS: InvalidClient "Assertion signature is invalid"
        else aud is neither the issuer nor the token endpoint
            CA--xS: InvalidClient "Assertion aud must be the issuer or the token endpoint"
        else exp missing or in the past
            CA--xS: InvalidClient "Assertion has expired"
        else jti missing
            CA--xS: InvalidClient "Assertion jti is required"
        else jti checked for replay
            CA->>AR: markUsed(client_id, jti, ttl until exp)
            AR->>R: SET assertion:{client_id}:{jti} 1 NX EX ttl
            alt key already existed
                R-->>AR: false
                CA--xS: InvalidClient "Assertion has already been used"
            else first use
                R-->>AR: true
                CA-->>S: ClientRegistration
            end
        end
    else PublicClient
        CA-->>S: ClientRegistration (registered for none)
    end
```
