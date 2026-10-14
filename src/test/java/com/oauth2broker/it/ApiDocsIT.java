package com.oauth2broker.it;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.jupiter.api.Test;

/// The OpenAPI document served by the running server over HTTPS.
class ApiDocsIT {

    @Test
    @SuppressWarnings("unchecked")
    void listsEveryEndpoint() {
        try (var broker = new Broker()) {
            var response = broker.get("/v3/api-docs");
            assertThat(response.status()).isEqualTo(200);

            var paths = (Map<String, Object>) Broker.json(response).get("paths");
            assertThat(paths).containsOnlyKeys("/authorize", "/token", "/revoke", "/userinfo", "/jwks",
                    "/.well-known/openid-configuration");
            assertThat((Map<String, Object>) paths.get("/authorize")).containsKeys("get", "post");
            assertThat((Map<String, Object>) paths.get("/userinfo")).containsKeys("get", "post");
        }
    }
}
