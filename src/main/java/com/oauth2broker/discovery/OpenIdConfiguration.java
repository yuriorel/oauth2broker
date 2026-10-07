package com.oauth2broker.discovery;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.oauth2broker.client.AuthMethod;

/** OpenID Provider metadata (OpenID Connect Discovery 1.0, RFC 8414). */
public record OpenIdConfiguration(
        @JsonProperty("issuer") String issuer,
        @JsonProperty("authorization_endpoint") String authorizationEndpoint,
        @JsonProperty("token_endpoint") String tokenEndpoint,
        @JsonProperty("revocation_endpoint") String revocationEndpoint,
        @JsonProperty("userinfo_endpoint") String userinfoEndpoint,
        @JsonProperty("jwks_uri") String jwksUri,
        @JsonProperty("response_types_supported") List<String> responseTypesSupported,
        @JsonProperty("grant_types_supported") List<String> grantTypesSupported,
        @JsonProperty("subject_types_supported") List<String> subjectTypesSupported,
        @JsonProperty("id_token_signing_alg_values_supported") List<String> idTokenSigningAlgValuesSupported,
        @JsonProperty("token_endpoint_auth_methods_supported") List<AuthMethod> tokenEndpointAuthMethodsSupported,
        @JsonProperty("token_endpoint_auth_signing_alg_values_supported") List<String> tokenEndpointAuthSigningAlgValuesSupported,
        @JsonProperty("revocation_endpoint_auth_methods_supported") List<AuthMethod> revocationEndpointAuthMethodsSupported,
        @JsonProperty("code_challenge_methods_supported") List<String> codeChallengeMethodsSupported,
        @JsonProperty("scopes_supported") List<String> scopesSupported,
        @JsonProperty("claims_supported") List<String> claimsSupported,
        @JsonProperty("authorization_response_iss_parameter_supported") boolean authorizationResponseIssParameterSupported) {

    public static OpenIdConfiguration forIssuer(String issuer) {
        var authMethods = List.of(AuthMethod.values());
        return new OpenIdConfiguration(
                issuer,
                issuer + "/authorize",
                issuer + "/token",
                issuer + "/revoke",
                issuer + "/userinfo",
                issuer + "/jwks",
                List.of("code"),
                List.of("authorization_code", "refresh_token"),
                List.of("public"),
                List.of("RS256"),
                authMethods,
                List.of("RS256", "ES256"),
                authMethods,
                List.of("S256"),
                List.of("openid", "profile", "email"),
                List.of("sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash",
                        "name", "email", "email_verified"),
                true);
    }
}
