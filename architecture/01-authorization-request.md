# Authorization request (GET /authorize)

The browser arrives from the client application. An unknown client or unregistered `redirect_uri` is shown as an HTML error page, because redirecting there would be unsafe. Every other error is redirected back to the client with `error`, `error_description`, `state` and `iss`.

```mermaid
sequenceDiagram
    autonumber
    actor U as User (browser)
    participant AC as AuthorizationController
    participant AS as AuthorizationService
    participant CR as ClientRepository
    participant RR as AuthorizationRequestRepository
    participant R as Redis

    U->>AC: GET /authorize?response_type, client_id, redirect_uri,<br/>scope, state, nonce, code_challenge, code_challenge_method
    AC->>AS: authorize(AuthorizeParams)
    AS->>CR: find(client_id)
    CR->>R: GET client:{client_id}
    R-->>CR: ClientRegistration or nil
    CR-->>AS: Optional

    alt client_id missing or unknown
        AS-->>AC: ErrorPage("Unknown client.")
        AC-->>U: 400 HTML error page
    else redirect_uri missing or not registered
        AS-->>AC: ErrorPage("The redirect URI is not registered ...")
        AC-->>U: 400 HTML error page
    else request invalid
        Note over AS: Checked in order:<br/>response_type missing: invalid_request<br/>response_type not code: unsupported_response_type<br/>scope missing: invalid_scope<br/>scope not allowed for client: invalid_scope<br/>code_challenge missing: invalid_request<br/>method not S256: invalid_request<br/>challenge not 43 base64url chars: invalid_request
        AS-->>AC: Redirect(redirect_uri?error, error_description, state, iss)
        AC-->>U: 302 Location: redirect_uri with error
    else valid
        AS->>RR: save(AuthorizationRequest)
        RR->>R: SET authreq:{id} JSON EX 10 min
        RR-->>AS: request id (256 random bits)
        AS-->>AC: LoginPage(request id, client_id)
        AC-->>U: 200 HTML login form (hidden request_id)<br/>Cache-Control: no-store, CSP frame-ancestors 'none'
    end
```
