# Discovery and JWKS

Both documents are built once when the controller is created and served as is. They have no error paths of their own; unexpected failures are handled as in [the request pipeline](00-request-pipeline.md).

```mermaid
sequenceDiagram
    autonumber
    participant App as Client app
    participant DC as DiscoveryController
    participant SK as SigningKey

    Note over DC,SK: At startup
    DC->>DC: OpenIdConfiguration.forIssuer(issuer)
    DC->>SK: publicJwkSet()
    SK-->>DC: public RS256 JWK (kid = RFC 7638 thumbprint)

    App->>DC: GET /.well-known/openid-configuration
    DC-->>App: 200 issuer, endpoints, supported grants, auth methods,<br/>S256, scopes, claims
    App->>DC: GET /jwks
    DC-->>App: 200 keys: [public JWK]
    Note over App: Verifies access and ID token signatures with the key whose kid matches
```
