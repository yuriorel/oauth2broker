package com.oauth2broker.it;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.microsoft.playwright.APIResponse;
import com.oauth2broker.it.Broker.Authorization;

/// Requests the broker must reject, against the running server.
class NegativePathsIT {

    private static Broker broker;

    @BeforeAll
    static void start() {
        broker = new Broker();
    }

    @AfterAll
    static void stop() {
        broker.close();
    }

    @Test
    void wrongPasswordShowsTheFormAgain() {
        var authorization = Authorization.of(TestClient.WEB_APP);
        try (var page = broker.open(authorization)) {
            assertThat(page.signIn("alice", "wrong").error()).isEqualTo("Invalid username or password.");

            var callback = page.signIn("alice", "wonderland").callback();
            assertThat(broker.redeem(authorization, callback.code()).status()).isEqualTo(200);
        }
    }

    @Test
    void wrongCodeVerifierIsRejected() {
        var authorization = Authorization.of(TestClient.WEB_APP);
        var code = broker.signIn(authorization).code();

        assertError(broker.redeem(TestClient.WEB_APP, code, Pkce.create().verifier()), 400, "invalid_grant");
    }

    @Test
    void codeCanBeRedeemedOnce() {
        var authorization = Authorization.of(TestClient.WEB_APP);
        var code = broker.signIn(authorization).code();

        assertThat(broker.redeem(authorization, code).status()).isEqualTo(200);
        assertError(broker.redeem(authorization, code), 400, "invalid_grant");
    }

    @Test
    void clientAssertionCanBeUsedOnce() {
        var assertion = TestClient.freshAssertion();
        var client = new TestClient.PrivateKeyJwt("jwt-app", () -> assertion);
        var authorization = Authorization.of(client);
        var code = broker.signIn(authorization).code();

        var tokens = broker.redeem(authorization, code);
        assertThat(tokens.status()).isEqualTo(200);
        var refreshToken = (String) Broker.json(tokens).get("refresh_token");
        assertError(broker.refresh(client, refreshToken), 401, "invalid_client");
    }

    @Test
    void revokedRefreshTokenIsRejected() {
        var authorization = Authorization.of(TestClient.WEB_APP);
        var tokens = broker.redeem(authorization, broker.signIn(authorization).code());
        var refreshToken = (String) Broker.json(tokens).get("refresh_token");

        assertThat(broker.revoke(TestClient.WEB_APP, refreshToken).status()).isEqualTo(200);
        assertError(broker.refresh(TestClient.WEB_APP, refreshToken), 400, "invalid_grant");
    }

    @Test
    void unregisteredRedirectUriShowsAnErrorPage() {
        var authorization = new Authorization(TestClient.WEB_APP, "https://evil.example/callback", Pkce.create(),
                "state", "nonce");
        try (var page = broker.open(authorization)) {
            assertThat(page.status()).isEqualTo(400);
            assertThat(page.text()).contains("The redirect URI is not registered for this client.");
        }
    }

    private static void assertError(APIResponse response, int status, String error) {
        assertThat(response.status()).isEqualTo(status);
        assertThat(Broker.json(response)).containsEntry("error", error);
    }
}
