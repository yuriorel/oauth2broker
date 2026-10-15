# Sign-in and authorization code (POST /authorize)

The login form posts the pending request id with the credentials. On success the request is consumed with `GETDEL`, so a concurrent second sign-in for the same request fails.

```mermaid
sequenceDiagram
    autonumber
    actor U as User (browser)
    participant AC as AuthorizationController
    participant AS as AuthorizationService
    participant RR as AuthorizationRequestRepository
    participant UR as UserRepository
    participant PE as PasswordEncoder (BCrypt)
    participant CoR as AuthorizationCodeRepository
    participant R as Redis
    participant App as Client app (redirect_uri)

    U->>AC: POST /authorize request_id, username, password
    AC->>AS: login(request_id, username, password)
    AS->>RR: find(request_id)
    RR->>R: GET authreq:{id}
    R-->>RR: AuthorizationRequest or nil

    alt request_id missing, unknown or expired
        AS-->>AC: ErrorPage("The sign-in request has expired or is unknown ...")
        AC-->>U: 400 HTML error page
    else request found
        AS->>UR: find(username)
        UR->>R: GET user:{username}
        R-->>UR: User or nil
        AS->>PE: matches(password, passwordHash)
        alt unknown user, missing or wrong password
            AS-->>AC: LoginPage(request_id, client_id, username, "Invalid username or password.")
            AC-->>U: 200 HTML login form with error (request stays pending)
        else credentials valid
            AS->>RR: take(request_id)
            RR->>R: GETDEL authreq:{id}
            alt already taken by a concurrent sign-in
                R-->>RR: nil
                AS-->>AC: ErrorPage("The sign-in request has already been used.")
                AC-->>U: 400 HTML error page
            else taken
                R-->>RR: AuthorizationRequest
                AS->>CoR: save(AuthorizationCode(client, redirect_uri, user, scope, nonce, challenge, auth_time))
                CoR->>R: SET code:{code} JSON EX 60 s
                CoR-->>AS: code (256 random bits)
                AS-->>AC: Redirect(redirect_uri?code, state, iss)
                AC-->>U: 302 Location (Cache-Control: no-store)
                U->>App: GET redirect_uri?code=...&state=...&iss=...
            end
        end
    end
```
