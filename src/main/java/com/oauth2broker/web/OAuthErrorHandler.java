package com.oauth2broker.web;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.oauth2broker.web.OAuthException.InsufficientScope;
import com.oauth2broker.web.OAuthException.InvalidClient;
import com.oauth2broker.web.OAuthException.InvalidToken;

/**
 * Turns {@link OAuthException} into the JSON error response of RFC 6749 section 5.2. Bearer token errors also get
 * the {@code WWW-Authenticate: Bearer} challenge of RFC 6750 section 3.
 */
@RestControllerAdvice
public class OAuthErrorHandler {

    private static final String REALM = "realm=\"oauth2broker\"";

    @ExceptionHandler
    ResponseEntity<ErrorResponse> handle(OAuthException e) {
        var response = switch (e) {
            case InvalidClient _ -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.WWW_AUTHENTICATE, "Basic " + REALM);
            case InvalidToken _ -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.WWW_AUTHENTICATE, bearerChallenge(e));
            case InsufficientScope _ -> ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .header(HttpHeaders.WWW_AUTHENTICATE, bearerChallenge(e));
            default -> ResponseEntity.badRequest();
        };
        return response.cacheControl(CacheControl.noStore()).body(new ErrorResponse(e.error(), e.getMessage()));
    }

    /** The description is already limited to characters allowed in a quoted string. */
    private static String bearerChallenge(OAuthException e) {
        return "Bearer %s, error=\"%s\", error_description=\"%s\"".formatted(REALM, e.error(), e.getMessage());
    }
}
