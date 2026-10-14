package com.oauth2broker.it;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.stream.Stream;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.oauth2broker.it.Broker.Authorization;

/// The full authorization code flow for each client type, against the running server.
class AuthorizationCodeFlowIT {

    private static Broker broker;

    @BeforeAll
    static void start() {
        broker = new Broker();
    }

    @AfterAll
    static void stop() {
        broker.close();
    }

    static Stream<Named<TestClient>> clients() {
        return Stream.of(TestClient.WEB_APP, TestClient.JWT_APP, TestClient.SPA_APP)
                .map(client -> Named.of(client.id(), client));
    }

    @ParameterizedTest
    @MethodSource("clients")
    void signInRedeemRefreshAndRevoke(TestClient client) throws Exception {
        var authorization = Authorization.of(client);

        var callback = broker.signIn(authorization);
        assertThat(callback.state()).isEqualTo(authorization.state());
        assertThat(callback.query()).containsEntry("iss", Broker.BASE_URL);

        var tokens = broker.redeem(authorization, callback.code());
        assertThat(tokens.status()).isEqualTo(200);
        var body = Broker.json(tokens);
        assertThat(body).containsEntry("token_type", "Bearer").containsEntry("scope", Broker.SCOPE);

        var idToken = broker.verify((String) body.get("id_token"));
        assertThat(idToken.getIssuer()).isEqualTo(Broker.BASE_URL);
        assertThat(idToken.getSubject()).isEqualTo("alice");
        assertThat(idToken.getAudience()).containsExactly(client.id());
        assertThat(idToken.getStringClaim("nonce")).isEqualTo(authorization.nonce());
        var accessToken = (String) body.get("access_token");
        assertThat(broker.verify(accessToken).getStringClaim("client_id")).isEqualTo(client.id());

        var userInfo = broker.userInfo(accessToken);
        assertThat(userInfo.status()).isEqualTo(200);
        assertThat(Broker.json(userInfo)).containsEntry("sub", "alice").containsEntry("email", "alice@example.com");

        var refreshed = broker.refresh(client, (String) body.get("refresh_token"));
        assertThat(refreshed.status()).isEqualTo(200);
        var newAccessToken = (String) Broker.json(refreshed).get("access_token");
        assertThat(Broker.json(refreshed).get("refresh_token")).isNotEqualTo(body.get("refresh_token"));
        assertThat(broker.userInfo(newAccessToken).status()).isEqualTo(200);

        assertThat(broker.revoke(client, newAccessToken).status()).isEqualTo(200);
        var revoked = broker.userInfo(newAccessToken);
        assertThat(revoked.status()).isEqualTo(401);
        assertThat(revoked.headers().get("www-authenticate")).contains("error=\"invalid_token\"");
    }
}
