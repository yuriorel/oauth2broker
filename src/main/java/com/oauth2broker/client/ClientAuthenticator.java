package com.oauth2broker.client;

import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.oauth2broker.client.ClientCredentials.PrivateKeyJwt;
import com.oauth2broker.client.ClientCredentials.PublicClient;
import com.oauth2broker.client.ClientCredentials.SecretBasic;
import com.oauth2broker.config.BrokerProperties;
import com.oauth2broker.web.OAuthException.InvalidClient;

/** Authenticates clients with the method they registered: {@code client_secret_basic}, {@code private_key_jwt} or {@code none}. */
@Service
public class ClientAuthenticator {

    private static final Set<JWSAlgorithm> ALGORITHMS = Set.of(JWSAlgorithm.RS256, JWSAlgorithm.ES256);

    private final ClientRepository clients;
    private final AssertionReplayRepository replay;
    private final PasswordEncoder passwords;
    private final List<String> audiences;
    private final Clock clock;

    public ClientAuthenticator(ClientRepository clients, AssertionReplayRepository replay, PasswordEncoder passwords,
                               BrokerProperties properties, Clock clock) {
        this.clients = clients;
        this.replay = replay;
        this.passwords = passwords;
        this.audiences = List.of(properties.issuer(), properties.issuer() + "/token");
        this.clock = clock;
    }

    public ClientRegistration authenticate(ClientCredentials credentials) {
        return switch (credentials) {
            case SecretBasic(var clientId, var secret) -> {
                var client = registered(clientId, AuthMethod.CLIENT_SECRET_BASIC);
                if (!passwords.matches(secret, client.clientSecretHash())) {
                    throw new InvalidClient("Client authentication failed");
                }
                yield client;
            }
            case PrivateKeyJwt(var clientId, var assertion) -> verifyAssertion(clientId, assertion);
            case PublicClient(var clientId) -> registered(clientId, AuthMethod.NONE);
        };
    }

    private ClientRegistration registered(String clientId, AuthMethod method) {
        return clients.find(clientId)
                .filter(client -> client.tokenEndpointAuthMethod() == method)
                .orElseThrow(() -> new InvalidClient("Client authentication failed"));
    }

    /** RFC 7523 section 3: signature, {@code iss} = {@code sub} = client, {@code aud}, {@code exp} and a single-use {@code jti}. */
    private ClientRegistration verifyAssertion(String clientIdParam, String assertion) {
        try {
            var jwt = SignedJWT.parse(assertion);
            var claims = jwt.getJWTClaimsSet();
            var clientId = claims.getIssuer();
            if (clientId == null || !clientId.equals(claims.getSubject())
                    || (clientIdParam != null && !clientIdParam.equals(clientId))) {
                throw new InvalidClient("Assertion iss and sub must be the client_id");
            }
            var client = registered(clientId, AuthMethod.PRIVATE_KEY_JWT);
            var algorithm = jwt.getHeader().getAlgorithm();
            if (!ALGORITHMS.contains(algorithm)) {
                throw new InvalidClient("Assertion must be signed with RS256 or ES256");
            }
            var verified = JWKSet.parse(client.jwks()).getKeys().stream()
                    .filter(key -> jwt.getHeader().getKeyID() == null || jwt.getHeader().getKeyID().equals(key.getKeyID()))
                    .map(key -> verifier(key, algorithm))
                    .filter(verifier -> verifier != null && verify(jwt, verifier))
                    .findFirst();
            if (verified.isEmpty()) {
                throw new InvalidClient("Assertion signature is invalid");
            }
            if (claims.getAudience().stream().noneMatch(audiences::contains)) {
                throw new InvalidClient("Assertion aud must be the issuer or the token endpoint");
            }
            var now = clock.instant();
            var expiry = claims.getExpirationTime();
            if (expiry == null || !expiry.after(Date.from(now))) {
                throw new InvalidClient("Assertion has expired");
            }
            if (claims.getJWTID() == null) {
                throw new InvalidClient("Assertion jti is required");
            }
            if (!replay.markUsed(clientId, claims.getJWTID(), Duration.between(now, expiry.toInstant()))) {
                throw new InvalidClient("Assertion has already been used");
            }
            return client;
        } catch (ParseException _) {
            throw new InvalidClient("Malformed client assertion");
        }
    }

    /** A verifier when the key type fits the algorithm, otherwise null. */
    private static JWSVerifier verifier(JWK key, JWSAlgorithm algorithm) {
        try {
            return switch (key) {
                case RSAKey rsa when algorithm.equals(JWSAlgorithm.RS256) -> new RSASSAVerifier(rsa);
                case ECKey ec when algorithm.equals(JWSAlgorithm.ES256) -> new ECDSAVerifier(ec);
                default -> null;
            };
        } catch (JOSEException _) {
            return null;
        }
    }

    private static boolean verify(SignedJWT jwt, JWSVerifier verifier) {
        try {
            return jwt.verify(verifier);
        } catch (JOSEException _) {
            return false;
        }
    }
}
