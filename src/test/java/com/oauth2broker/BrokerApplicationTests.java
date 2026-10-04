package com.oauth2broker;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.oauth2broker.config.BrokerProperties;

@SpringBootTest
class BrokerApplicationTests {

    @Autowired
    BrokerProperties properties;

    @Test
    void contextLoadsAndBindsProperties() {
        assertThat(properties.issuer()).isEqualTo("https://localhost:8443");
        assertThat(properties.keystore().signingAlias()).isEqualTo("signing");
        assertThat(properties.ttl().authorizationCode()).isEqualTo(Duration.ofSeconds(60));
        assertThat(properties.ttl().refreshToken()).isEqualTo(Duration.ofDays(30));
    }
}
