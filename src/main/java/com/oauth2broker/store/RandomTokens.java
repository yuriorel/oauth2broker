package com.oauth2broker.store;

import java.security.SecureRandom;
import java.util.Base64;

/** Opaque, unguessable values for codes, request ids and refresh tokens. */
public final class RandomTokens {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    private RandomTokens() {
    }

    /** 256 random bits, base64url encoded. */
    public static String generate() {
        var bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return ENCODER.encodeToString(bytes);
    }
}
