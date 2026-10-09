package com.oauth2broker.jose;

import module java.base;

import org.springframework.stereotype.Component;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.oauth2broker.config.BrokerProperties;

/** Issues RS256-signed access tokens (RFC 9068) and ID tokens (OpenID Connect Core). */
@Component
public class TokenSigner {

    static final JOSEObjectType ACCESS_TOKEN_TYPE = new JOSEObjectType("at+jwt");

    private final SigningKey key;
    private final RSASSASigner signer;
    private final String issuer;
    private final Duration ttl;
    private final Clock clock;

    public TokenSigner(SigningKey key, BrokerProperties properties, Clock clock) throws JOSEException {
        this.key = key;
        this.signer = new RSASSASigner(key.jwk());
        this.issuer = properties.issuer();
        this.ttl = properties.ttl().accessToken();
        this.clock = clock;
    }

    public SignedAccessToken accessToken(String clientId, String username, Set<String> scope) {
        var now = clock.instant();
        var expiresAt = now.plus(ttl);
        var jti = UUID.randomUUID().toString();
        var claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(username)
                .audience(issuer)
                .claim("client_id", clientId)
                .claim("scope", String.join(" ", scope))
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiresAt))
                .jwtID(jti)
                .build();
        return new SignedAccessToken(sign(ACCESS_TOKEN_TYPE, claims), jti, expiresAt);
    }

    /** An ID token for {@code clientId}. A null {@code nonce} is left out. */
    public String idToken(String clientId, String username, String nonce, Instant authTime, String accessToken) {
        var now = clock.instant();
        var claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(username)
                .audience(clientId)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(ttl)))
                .claim("auth_time", authTime.getEpochSecond())
                .claim("nonce", nonce)
                .claim("at_hash", atHash(accessToken))
                .build();
        return sign(JOSEObjectType.JWT, claims);
    }

    /** Left half of the SHA-256 of the access token, base64url encoded (OpenID Connect Core 3.1.3.6). */
    static String atHash(String accessToken) {
        try {
            var digest = MessageDigest.getInstance("SHA-256").digest(accessToken.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOf(digest, digest.length / 2));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private String sign(JOSEObjectType type, JWTClaimsSet claims) {
        var header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(type).keyID(key.keyId()).build();
        var jwt = new SignedJWT(header, claims);
        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
        return jwt.serialize();
    }
}
