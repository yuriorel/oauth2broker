package com.oauth2broker;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.oauth2broker.authorize.AuthorizationCode;
import com.oauth2broker.authorize.AuthorizationRequest;
import com.oauth2broker.client.AuthMethod;
import com.oauth2broker.client.ClientRegistration;
import com.oauth2broker.token.AccessTokenRecord;
import com.oauth2broker.token.RefreshTokenRecord;
import com.oauth2broker.user.User;

import tools.jackson.databind.json.JsonMapper;

/** Every value stored in Redis survives a JSON round trip. */
class RecordJsonTest {

    private final JsonMapper json = JsonMapper.builder().build();

    @Test
    void parsesClientRegistration() {
        var client = json.readValue("""
                {
                  "clientId": "jwt-app",
                  "tokenEndpointAuthMethod": "private_key_jwt",
                  "clientSecretHash": null,
                  "jwks": {"keys": [{"kty": "RSA", "kid": "k1", "e": "AQAB", "n": "abc"}]},
                  "redirectUris": ["http://localhost:8080/callback"],
                  "scopes": ["openid", "email"]
                }
                """, ClientRegistration.class);

        assertThat(client.tokenEndpointAuthMethod()).isEqualTo(AuthMethod.PRIVATE_KEY_JWT);
        assertThat(client.jwks()).containsKey("keys");
        assertThat(client.redirectUris()).containsExactly("http://localhost:8080/callback");
        assertThat(client.scopes()).containsExactlyInAnyOrder("openid", "email");
    }

    @Test
    void writesAuthMethodsWithOAuthNames() {
        assertThat(json.writeValueAsString(List.of(AuthMethod.values())))
                .isEqualTo("""
                        ["client_secret_basic","private_key_jwt","none"]""");
    }

    @Test
    void roundTripsEveryStoredRecord() {
        var scope = Set.of("openid", "profile");
        var records = List.of(
                new ClientRegistration("web-app", AuthMethod.CLIENT_SECRET_BASIC, "$2a$10$hash", null,
                        List.of("http://localhost:8080/callback"), scope),
                new ClientRegistration("jwt-app", AuthMethod.PRIVATE_KEY_JWT, null,
                        Map.of("keys", List.of(Map.of("kty", "RSA"))), List.of("http://localhost:8080/callback"), scope),
                new User("alice", "$2a$10$hash", "Alice", "alice@example.com", true),
                new AuthorizationRequest("web-app", "http://localhost:8080/callback", scope, "xyz", "n-1", "challenge"),
                new AuthorizationCode("web-app", "http://localhost:8080/callback", "alice", scope, null, "challenge",
                        Instant.parse("2026-10-05T12:00:00Z")),
                new AccessTokenRecord("web-app", "alice", scope),
                new RefreshTokenRecord("web-app", "alice", scope));

        for (var record : records) {
            assertThat(json.readValue(json.writeValueAsString(record), record.getClass())).isEqualTo(record);
        }
    }
}
