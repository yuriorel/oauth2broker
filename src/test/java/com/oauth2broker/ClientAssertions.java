package com.oauth2broker;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/** Builds RFC 7523 client assertions in tests, by default for {@code jwt-app} with its key from the test resources. */
public final class ClientAssertions {

    private static final RSAKey JWT_APP_KEY = load();

    private ClientAssertions() {
    }

    public static RSAKey jwtAppKey() {
        return JWT_APP_KEY;
    }

    /** A valid assertion: iss = sub = jwt-app, aud = token endpoint, expires in 60 s, random jti. */
    public static JWTClaimsSet.Builder claims(Instant now) {
        return new JWTClaimsSet.Builder()
                .issuer("jwt-app")
                .subject("jwt-app")
                .audience(TestProperties.ISSUER + "/token")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(60)))
                .jwtID(UUID.randomUUID().toString());
    }

    public static String sign(JWTClaimsSet claims) {
        return sign(JWT_APP_KEY, claims);
    }

    public static String sign(JWK key, JWTClaimsSet claims) {
        try {
            JWSSigner signer = key instanceof ECKey ec ? new ECDSASigner(ec) : new RSASSASigner((RSAKey) key);
            var algorithm = key instanceof ECKey ? JWSAlgorithm.ES256 : JWSAlgorithm.RS256;
            var jwt = new SignedJWT(new JWSHeader.Builder(algorithm).keyID(key.getKeyID()).build(), claims);
            jwt.sign(signer);
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static RSAKey load() {
        try (var in = ClientAssertions.class.getResourceAsStream("/jwt-app-key.json")) {
            return RSAKey.parse(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (ParseException e) {
            throw new IllegalStateException(e);
        }
    }
}
