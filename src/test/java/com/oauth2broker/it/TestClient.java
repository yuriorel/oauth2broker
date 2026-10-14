package com.oauth2broker.it;

import java.time.Instant;
import java.util.function.Supplier;

import com.oauth2broker.ClientAssertions;

/** A seeded client and how it authenticates at the token and revocation endpoints. */
sealed interface TestClient {

    String id();

    record SecretBasic(String id, String secret) implements TestClient {
    }

    /** {@code assertions} supplies the client assertion for each request. */
    record PrivateKeyJwt(String id, Supplier<String> assertions) implements TestClient {
    }

    record Public(String id) implements TestClient {
    }

    TestClient WEB_APP = new SecretBasic("web-app", "web-app-secret");
    TestClient JWT_APP = new PrivateKeyJwt("jwt-app", TestClient::freshAssertion);
    TestClient SPA_APP = new Public("spa-app");

    /** A new jwt-app assertion with a random {@code jti}, signed with the key from the test resources. */
    static String freshAssertion() {
        return ClientAssertions.sign(ClientAssertions.claims(Instant.now()).build());
    }
}
