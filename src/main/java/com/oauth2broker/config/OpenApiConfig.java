package com.oauth2broker.config;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;

/** Document-level OpenAPI settings. Operations and schemas are generated from the controllers. */
@Configuration(proxyBeanMethods = false)
public class OpenApiConfig {

    public static final String CLIENT_SECRET_BASIC = "clientSecretBasic";
    public static final String BEARER_AUTH = "bearerAuth";

    @Bean
    OpenAPI openApi(BrokerProperties properties) {
        return new OpenAPI()
                .info(new Info()
                        .title("OAuth 2 / OIDC Broker")
                        .version("0.1.0")
                        .description("Authorization code flow with PKCE, token, revocation and userinfo endpoints."))
                .servers(List.of(new Server().url(properties.issuer())))
                .components(new Components()
                        .addSecuritySchemes(CLIENT_SECRET_BASIC, new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("basic")
                                .description("client_secret_basic: client_id and client_secret as HTTP Basic credentials"))
                        .addSecuritySchemes(BEARER_AUTH, new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("Access token issued by the token endpoint")));
    }
}
