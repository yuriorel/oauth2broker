package com.oauth2broker.discovery;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.jwk.JWK;
import com.oauth2broker.config.BrokerProperties;
import com.oauth2broker.jose.SigningKey;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@Tag(name = "Discovery", description = "Metadata and keys that clients use to configure themselves and verify tokens")
public class DiscoveryController {

    private final OpenIdConfiguration configuration;
    private final JwkSet jwks;

    public DiscoveryController(BrokerProperties properties, SigningKey signingKey) {
        this.configuration = OpenIdConfiguration.forIssuer(properties.issuer());
        this.jwks = new JwkSet(signingKey.publicJwkSet().getKeys().stream().map(JWK::toJSONObject).toList());
    }

    @GetMapping(path = "/.well-known/openid-configuration", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "OpenID Provider metadata", description = "OpenID Connect Discovery 1.0 document.")
    public OpenIdConfiguration configuration() {
        return configuration;
    }

    @GetMapping(path = "/jwks", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Public signing keys", description = "JWK Set with the RS256 key that signs access and ID tokens.")
    public JwkSet jwks() {
        return jwks;
    }
}
