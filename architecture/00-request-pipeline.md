# Request pipeline and error handling

Every request passes through the same filters. Services signal OAuth errors by throwing a subclass of the sealed `OAuthException`; `OAuthErrorHandler` turns it into the RFC 6749 JSON error. The other flows refer to this diagram for the error responses.

```mermaid
sequenceDiagram
    autonumber
    participant C as Caller
    participant T as Tomcat (virtual thread)
    participant RID as RequestIdFilter
    participant LOG as HttpLoggingFilter
    participant DS as DispatcherServlet
    participant CT as Controller / Service
    participant EH as OAuthErrorHandler

    C->>T: HTTPS request
    T->>RID: doFilter
    RID->>RID: new RequestContext(random UUID)<br/>set X-Request-Id header
    RID->>LOG: ScopedValue.where(CURRENT, context).call(chain)
    alt DEBUG off, or path /v3/api-docs or /swagger-ui
        LOG->>DS: chain.doFilter (unwrapped)
    else DEBUG on
        LOG->>LOG: wrap in ContentCachingRequestWrapper / ResponseWrapper
        LOG->>DS: chain.doFilter (wrapped)
    end
    DS->>CT: handler method

    alt success
        CT-->>DS: ResponseEntity (200 / 302 / HTML 400)
    else OAuthException thrown
        CT--xDS: OAuthException
        DS->>EH: handle(e)
        EH->>EH: log.error "Request id rejected: error (description)"<br/>log.debug stack trace
        alt InvalidClient
            EH-->>DS: 401, WWW-Authenticate: Basic realm
        else InvalidToken
            EH-->>DS: 401, WWW-Authenticate: Bearer realm, error, error_description
        else InsufficientScope
            EH-->>DS: 403, WWW-Authenticate: Bearer realm, error, error_description
        else InvalidRequest, InvalidGrant, InvalidScope, UnsupportedGrantType
            EH-->>DS: 400
        end
        Note over EH,DS: Body ErrorResponse(error, error_description), Cache-Control: no-store
    else unexpected exception (for example Redis unavailable)
        CT--xDS: RuntimeException
        DS--xLOG: exception propagates
        LOG->>LOG: DEBUG: log request and "Request failed after n ms" with stack trace
        LOG--xRID: rethrow
        RID--xT: rethrow
        T-->>C: 500 (Spring Boot error page)
    end

    DS-->>LOG: response
    LOG->>LOG: DEBUG: log request and response (headers, body)<br/>copyBodyToResponse
    LOG-->>RID: return
    RID-->>C: response with X-Request-Id
```
