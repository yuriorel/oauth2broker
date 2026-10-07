package com.oauth2broker.jose;

import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

/** The RS256 key pair that signs tokens. Its key id is the JWK thumbprint (RFC 7638). */
public record SigningKey(RSAKey jwk) {

    public SigningKey(RSAPublicKey publicKey, PrivateKey privateKey) throws JOSEException {
        var jwk = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyIDFromThumbprint()
                .build();
        this(jwk);
    }

    public String keyId() {
        return jwk.getKeyID();
    }

    /** The JWK Set published at {@code /jwks}: the public key only. */
    public JWKSet publicJwkSet() {
        return new JWKSet(jwk.toPublicJWK());
    }

    /** Never print the private key. */
    @Override
    public String toString() {
        return "SigningKey[kid=" + keyId() + "]";
    }
}
