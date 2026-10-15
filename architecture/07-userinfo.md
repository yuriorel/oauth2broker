# UserInfo (GET or POST /userinfo)

The access token is verified locally (signature, type, issuer, expiry). Then the revocation check (`at:{jti}` still in Redis) and the user lookup run in parallel subtasks. Token errors answer 401 with `WWW-Authenticate: Bearer`, a missing `openid` scope 403.

```mermaid
sequenceDiagram
    autonumber
    participant App as Client app
    participant UC as UserInfoController
    participant US as UserInfoService
    participant AV as AccessTokenVerifier
    participant TR as TokenRepository
    participant UR as UserRepository
    participant R as Redis

    App->>UC: GET /userinfo, Authorization: Bearer access token
    UC->>US: userInfo(Authorization header)
    alt header missing or not Bearer
        US--xApp: 401 invalid_token "Bearer access token is required"
    end

    US->>AV: verify(token)
    alt not a parsable JWT
        AV--xApp: 401 invalid_token "Malformed access token"
    else alg not RS256, typ not at+jwt, or signature invalid
        AV--xApp: 401 invalid_token "Access token signature is invalid"
    else iss is not this server
        AV--xApp: 401 invalid_token "Access token was not issued by this server"
    else exp missing or in the past
        AV--xApp: 401 invalid_token "Access token has expired"
    else jti or sub missing
        AV--xApp: 401 invalid_token "Access token is missing jti or sub"
    else valid
        AV-->>US: JWTClaimsSet
    end

    alt scope claim not a string
        US--xApp: 401 invalid_token "Access token scope is malformed"
    else scope lacks openid
        US--xApp: 403 insufficient_scope "The openid scope is required"
    end

    par subtask 1
        US->>TR: findAccessToken(jti)
        TR->>R: GET at:{jti}
        R-->>TR: AccessTokenRecord or nil
    and subtask 2
        US->>UR: find(sub)
        UR->>R: GET user:{sub}
        R-->>UR: User or nil
    end
    US->>US: Subtasks.join(tasks)

    alt record gone (revoked or expired)
        US--xApp: 401 invalid_token "Access token has been revoked"
    else user deleted
        US--xApp: 401 invalid_token "User no longer exists"
    else ok
        US->>US: UserInfo.of(user, scope)<br/>profile: name, email: email and email_verified
        US-->>UC: UserInfo
        UC-->>App: 200 sub, name, email, email_verified (Cache-Control: no-store)
    end
```
