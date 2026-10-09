package com.oauth2broker.web;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Error body of the token and revocation endpoints (RFC 6749 section 5.2). */
public record ErrorResponse(@JsonProperty("error") String error,
                            @JsonProperty("error_description") String errorDescription) {
}
