package com.oauth2broker.client;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Client authentication methods at the token endpoint, serialized with their OAuth names. */
public enum AuthMethod {
    @JsonProperty("client_secret_basic") CLIENT_SECRET_BASIC,
    @JsonProperty("private_key_jwt") PRIVATE_KEY_JWT,
    @JsonProperty("none") NONE
}
