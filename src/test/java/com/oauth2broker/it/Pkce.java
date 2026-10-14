package com.oauth2broker.it;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/// A PKCE verifier and its S256 challenge (RFC 7636).
record Pkce(String verifier, String challenge) {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();

    static Pkce create() {
        var bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        var verifier = BASE64URL.encodeToString(bytes);
        try {
            var digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return new Pkce(verifier, BASE64URL.encodeToString(digest));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
