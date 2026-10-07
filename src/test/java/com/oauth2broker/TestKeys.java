package com.oauth2broker;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

import com.oauth2broker.jose.SigningKey;

/** A signing key generated once per test run. */
public final class TestKeys {

    private static final SigningKey SIGNING_KEY = generate();

    private TestKeys() {
    }

    public static SigningKey signingKey() {
        return SIGNING_KEY;
    }

    public static SigningKey generate() {
        try {
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            var pair = generator.generateKeyPair();
            return new SigningKey((RSAPublicKey) pair.getPublic(), pair.getPrivate());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
