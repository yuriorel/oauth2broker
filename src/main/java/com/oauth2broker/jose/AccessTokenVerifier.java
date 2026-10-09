package com.oauth2broker.jose;

import java.text.ParseException;
import java.time.Clock;
import java.util.Date;

import org.springframework.stereotype.Component;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.oauth2broker.config.BrokerProperties;
import com.oauth2broker.web.OAuthException.InvalidToken;

/** Verifies access tokens issued by {@link TokenSigner}: RS256 signature, {@code typ: at+jwt}, issuer and expiry. */
@Component
public class AccessTokenVerifier {

    private final RSASSAVerifier verifier;
    private final String issuer;
    private final Clock clock;

    public AccessTokenVerifier(SigningKey key, BrokerProperties properties, Clock clock) throws JOSEException {
        this.verifier = new RSASSAVerifier(key.jwk().toRSAPublicKey());
        this.issuer = properties.issuer();
        this.clock = clock;
    }

    /** Returns the claims of a valid token. The caller still has to check that it has not been revoked. */
    public JWTClaimsSet verify(String token) {
        try {
            var jwt = SignedJWT.parse(token);
            var header = jwt.getHeader();
            if (!JWSAlgorithm.RS256.equals(header.getAlgorithm())
                    || !TokenSigner.ACCESS_TOKEN_TYPE.equals(header.getType()) || !jwt.verify(verifier)) {
                throw new InvalidToken("Access token signature is invalid");
            }
            var claims = jwt.getJWTClaimsSet();
            if (!issuer.equals(claims.getIssuer())) {
                throw new InvalidToken("Access token was not issued by this server");
            }
            var expiry = claims.getExpirationTime();
            if (expiry == null || !expiry.after(Date.from(clock.instant()))) {
                throw new InvalidToken("Access token has expired");
            }
            if (claims.getJWTID() == null || claims.getSubject() == null) {
                throw new InvalidToken("Access token is missing jti or sub");
            }
            return claims;
        } catch (ParseException | JOSEException _) {
            throw new InvalidToken("Malformed access token");
        }
    }
}
