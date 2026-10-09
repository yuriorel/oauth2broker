package com.oauth2broker.token;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Successful token response (RFC 6749 section 5.1). {@code id_token} is present only for the {@code openid} scope. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TokenResponse(@JsonProperty("access_token") String accessToken,
                            @JsonProperty("token_type") String tokenType,
                            @JsonProperty("expires_in") long expiresIn,
                            @JsonProperty("refresh_token") String refreshToken,
                            @JsonProperty("id_token") String idToken,
                            @JsonProperty("scope") String scope) {
}
