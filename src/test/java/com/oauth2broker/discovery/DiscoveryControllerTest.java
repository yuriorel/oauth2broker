package com.oauth2broker.discovery;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.oauth2broker.TestKeys;
import com.oauth2broker.TestProperties;

import tools.jackson.databind.json.JsonMapper;

class DiscoveryControllerTest {

    private final DiscoveryController controller =
            new DiscoveryController(TestProperties.create(), TestKeys.signingKey());
    private final JsonMapper json = JsonMapper.builder().build();

    @Test
    void configurationListsEndpointsUnderTheIssuer() {
        var config = controller.configuration();

        assertThat(config.issuer()).isEqualTo("https://localhost:8443");
        assertThat(config.authorizationEndpoint()).isEqualTo("https://localhost:8443/authorize");
        assertThat(config.tokenEndpoint()).isEqualTo("https://localhost:8443/token");
        assertThat(config.revocationEndpoint()).isEqualTo("https://localhost:8443/revoke");
        assertThat(config.userinfoEndpoint()).isEqualTo("https://localhost:8443/userinfo");
        assertThat(config.jwksUri()).isEqualTo("https://localhost:8443/jwks");
    }

    @Test
    void configurationSerializesWithDiscoveryNames() {
        var node = json.readTree(json.writeValueAsString(controller.configuration()));

        assertThat(node.get("code_challenge_methods_supported").toString()).isEqualTo("[\"S256\"]");
        assertThat(node.get("token_endpoint_auth_methods_supported").toString())
                .isEqualTo("[\"client_secret_basic\",\"private_key_jwt\",\"none\"]");
        assertThat(node.get("token_endpoint_auth_signing_alg_values_supported").toString())
                .isEqualTo("[\"RS256\",\"ES256\"]");
        assertThat(node.get("scopes_supported").toString()).isEqualTo("[\"openid\",\"profile\",\"email\"]");
        assertThat(node.get("response_types_supported").toString()).isEqualTo("[\"code\"]");
        assertThat(node.get("grant_types_supported").toString()).isEqualTo("[\"authorization_code\",\"refresh_token\"]");
        assertThat(node.get("id_token_signing_alg_values_supported").toString()).isEqualTo("[\"RS256\"]");
        assertThat(node.get("claims_supported").toString()).contains("\"email_verified\"");
        assertThat(node.get("authorization_response_iss_parameter_supported").booleanValue()).isTrue();
    }

    @Test
    void jwksPublishesOnlyThePublicSigningKey() {
        var keys = controller.jwks().keys();

        assertThat(keys).singleElement().satisfies(key -> {
            assertThat(key).containsEntry("kid", TestKeys.signingKey().keyId())
                    .containsEntry("kty", "RSA")
                    .containsEntry("use", "sig")
                    .containsEntry("alg", "RS256")
                    .containsKeys("n", "e")
                    .doesNotContainKeys("d", "p", "q", "dp", "dq", "qi");
        });
    }
}
