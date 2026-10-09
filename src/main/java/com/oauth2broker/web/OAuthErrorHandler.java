package com.oauth2broker.web;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.oauth2broker.web.OAuthException.InvalidClient;

/** Turns {@link OAuthException} into the JSON error response of RFC 6749 section 5.2. */
@RestControllerAdvice
public class OAuthErrorHandler {

    @ExceptionHandler
    ResponseEntity<ErrorResponse> handle(OAuthException e) {
        var response = switch (e) {
            case InvalidClient _ -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"oauth2broker\"");
            default -> ResponseEntity.badRequest();
        };
        return response.cacheControl(CacheControl.noStore()).body(new ErrorResponse(e.error(), e.getMessage()));
    }
}
