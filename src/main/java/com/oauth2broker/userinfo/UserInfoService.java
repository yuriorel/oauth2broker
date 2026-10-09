package com.oauth2broker.userinfo;

import java.text.ParseException;
import java.util.Set;
import java.util.concurrent.StructuredTaskScope;

import org.springframework.stereotype.Service;

import com.nimbusds.jwt.JWTClaimsSet;
import com.oauth2broker.jose.AccessTokenVerifier;
import com.oauth2broker.token.TokenRepository;
import com.oauth2broker.user.UserRepository;
import com.oauth2broker.web.OAuthException.InsufficientScope;
import com.oauth2broker.web.OAuthException.InvalidToken;
import com.oauth2broker.web.Scopes;
import com.oauth2broker.web.Subtasks;

/**
 * Returns the claims of the user an access token was issued for. After the token is verified, the revocation check
 * ({@code at:{jti}} still in Redis) and the user lookup run as parallel subtasks on virtual threads.
 */
@Service
public class UserInfoService {

    private final AccessTokenVerifier verifier;
    private final TokenRepository tokens;
    private final UserRepository users;

    public UserInfoService(AccessTokenVerifier verifier, TokenRepository tokens, UserRepository users) {
        this.verifier = verifier;
        this.tokens = tokens;
        this.users = users;
    }

    /** {@code authorization} is the {@code Authorization} header, or null if there is none. */
    public UserInfo userInfo(String authorization) {
        if (authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            throw new InvalidToken("Bearer access token is required");
        }
        var claims = verifier.verify(authorization.substring(7).strip());
        var scope = scopeOf(claims);
        if (!scope.contains("openid")) {
            throw new InsufficientScope("The openid scope is required");
        }
        try (var tasks = StructuredTaskScope.open()) {
            var record = tasks.fork(() -> tokens.findAccessToken(claims.getJWTID()));
            var user = tasks.fork(() -> users.find(claims.getSubject()));
            Subtasks.join(tasks);

            if (record.get().isEmpty()) {
                throw new InvalidToken("Access token has been revoked");
            }
            return UserInfo.of(user.get().orElseThrow(() -> new InvalidToken("User no longer exists")), scope);
        }
    }

    private static Set<String> scopeOf(JWTClaimsSet claims) {
        try {
            var scope = claims.getStringClaim("scope");
            return scope == null || scope.isBlank() ? Set.of() : Scopes.parse(scope);
        } catch (ParseException _) {
            throw new InvalidToken("Access token scope is malformed");
        }
    }
}
