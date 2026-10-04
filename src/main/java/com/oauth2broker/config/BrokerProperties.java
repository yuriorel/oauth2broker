package com.oauth2broker.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

@ConfigurationProperties("broker")
public record BrokerProperties(String issuer, Keystore keystore, Ttl ttl) {

    public record Keystore(Resource location, String password, String signingAlias) {
    }

    public record Ttl(Duration authorizationRequest, Duration authorizationCode, Duration accessToken,
                      Duration refreshToken) {
    }
}
