package com.oauth2broker.config;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.nimbusds.jose.JOSEException;
import com.oauth2broker.jose.SigningKey;

@Configuration(proxyBeanMethods = false)
public class BrokerConfig {

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    /** Checks the BCrypt hashes of user passwords and client secrets. */
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /** Loads the signing key pair from the PKCS12 keystore created by {@code scripts/gen-keystore}. */
    @Bean
    SigningKey signingKey(BrokerProperties properties) throws IOException, GeneralSecurityException, JOSEException {
        var keystore = properties.keystore();
        var password = keystore.password().toCharArray();
        var store = KeyStore.getInstance("PKCS12");
        try (var in = keystore.location().getInputStream()) {
            store.load(in, password);
        }
        var publicKey = (RSAPublicKey) store.getCertificate(keystore.signingAlias()).getPublicKey();
        var privateKey = (PrivateKey) store.getKey(keystore.signingAlias(), password);
        return new SigningKey(publicKey, privateKey);
    }
}
