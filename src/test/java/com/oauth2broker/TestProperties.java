package com.oauth2broker;

import java.time.Duration;

import com.oauth2broker.config.BrokerProperties;

/** {@link BrokerProperties} for unit tests, matching {@code application.yml}. */
public final class TestProperties {

    public static final String ISSUER = "https://localhost:8443";

    private TestProperties() {
    }

    public static BrokerProperties create() {
        return new BrokerProperties(ISSUER, null, new BrokerProperties.Ttl(
                Duration.ofMinutes(10), Duration.ofSeconds(60), Duration.ofMinutes(15), Duration.ofDays(30)));
    }
}
