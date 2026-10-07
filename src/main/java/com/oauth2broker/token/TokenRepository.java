package com.oauth2broker.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Optional;

import org.springframework.stereotype.Repository;

import com.oauth2broker.config.BrokerProperties;
import com.oauth2broker.store.RandomTokens;
import com.oauth2broker.store.RedisJsonStore;

/** Access tokens are keyed by {@code jti}; refresh tokens by their SHA-256 hash, so Redis never holds them in clear. */
@Repository
public class TokenRepository {

    private static final String ACCESS_PREFIX = "at:";
    private static final String REFRESH_PREFIX = "rt:";

    private final RedisJsonStore store;
    private final Duration accessTtl;
    private final Duration refreshTtl;

    public TokenRepository(RedisJsonStore store, BrokerProperties properties) {
        this.store = store;
        this.accessTtl = properties.ttl().accessToken();
        this.refreshTtl = properties.ttl().refreshToken();
    }

    public void saveAccessToken(String jti, AccessTokenRecord token) {
        store.set(ACCESS_PREFIX + jti, token, accessTtl);
    }

    public Optional<AccessTokenRecord> findAccessToken(String jti) {
        return store.get(ACCESS_PREFIX + jti, AccessTokenRecord.class);
    }

    public void deleteAccessToken(String jti) {
        store.delete(ACCESS_PREFIX + jti);
    }

    /** Stores the record and returns the new opaque refresh token. */
    public String saveRefreshToken(RefreshTokenRecord token) {
        var value = RandomTokens.generate();
        store.set(refreshKey(value), token, refreshTtl);
        return value;
    }

    public Optional<RefreshTokenRecord> findRefreshToken(String token) {
        return store.get(refreshKey(token), RefreshTokenRecord.class);
    }

    /** Reads and deletes the refresh token atomically, for rotation. */
    public Optional<RefreshTokenRecord> takeRefreshToken(String token) {
        return store.getAndDelete(refreshKey(token), RefreshTokenRecord.class);
    }

    public void deleteRefreshToken(String token) {
        store.delete(refreshKey(token));
    }

    private static String refreshKey(String token) {
        try {
            var hash = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.US_ASCII));
            return REFRESH_PREFIX + HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
