package com.oauth2broker.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import com.oauth2broker.client.ClientCredentials.PrivateKeyJwt;
import com.oauth2broker.client.ClientCredentials.PublicClient;
import com.oauth2broker.client.ClientCredentials.SecretBasic;
import com.oauth2broker.web.OAuthException.InvalidClient;
import com.oauth2broker.web.OAuthException.InvalidRequest;

class ClientCredentialsTest {

    private static String basic(String credentials) {
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void basicHeaderGivesSecretBasicWithFormDecodedValues() {
        assertThat(ClientCredentials.from(basic("web-app:s%3Acret+x"), null, null, null))
                .isEqualTo(new SecretBasic("web-app", "s:cret x"));
        assertThat(ClientCredentials.from(basic("web-app:").replace("Basic", "basic"), "ignored", null, null))
                .isEqualTo(new SecretBasic("web-app", ""));
    }

    @Test
    void secretIsNotPrinted() {
        assertThat(new SecretBasic("web-app", "hunter2").toString()).doesNotContain("hunter2");
    }

    @Test
    void malformedBasicHeaderIsInvalidClient() {
        assertThatThrownBy(() -> ClientCredentials.from("Basic !!!", null, null, null))
                .isInstanceOf(InvalidClient.class);
        assertThatThrownBy(() -> ClientCredentials.from(basic("no-colon"), null, null, null))
                .isInstanceOf(InvalidClient.class);
    }

    @Test
    void assertionGivesPrivateKeyJwt() {
        assertThat(ClientCredentials.from(null, null, ClientCredentials.JWT_BEARER, "a.b.c"))
                .isEqualTo(new PrivateKeyJwt(null, "a.b.c"));
        assertThat(ClientCredentials.from("Bearer x", "jwt-app", ClientCredentials.JWT_BEARER, "a.b.c"))
                .isEqualTo(new PrivateKeyJwt("jwt-app", "a.b.c"));
    }

    @Test
    void assertionWithWrongTypeIsInvalidClient() {
        assertThatThrownBy(() -> ClientCredentials.from(null, null, "urn:other", "a.b.c"))
                .isInstanceOf(InvalidClient.class);
        assertThatThrownBy(() -> ClientCredentials.from(null, null, null, "a.b.c"))
                .isInstanceOf(InvalidClient.class);
    }

    @Test
    void clientIdAloneGivesPublicClient() {
        assertThat(ClientCredentials.from(null, "spa-app", null, null)).isEqualTo(new PublicClient("spa-app"));
    }

    @Test
    void twoMethodsAreInvalidRequest() {
        assertThatThrownBy(() -> ClientCredentials.from(basic("a:b"), null, ClientCredentials.JWT_BEARER, "a.b.c"))
                .isInstanceOf(InvalidRequest.class);
    }

    @Test
    void noCredentialsAreInvalidClient() {
        assertThatThrownBy(() -> ClientCredentials.from(null, null, null, null)).isInstanceOf(InvalidClient.class);
    }
}
