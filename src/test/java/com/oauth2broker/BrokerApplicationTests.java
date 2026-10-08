package com.oauth2broker;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import com.oauth2broker.client.AuthMethod;
import com.oauth2broker.client.ClientRepository;
import com.oauth2broker.config.BrokerProperties;
import com.oauth2broker.jose.SigningKey;
import com.oauth2broker.store.SeedLoader;
import com.oauth2broker.user.UserRepository;

/** Starts the full context against the local Redis and the real keystore; startup runs the seeding. */
@SpringBootTest
@AutoConfigureMockMvc
class BrokerApplicationTests {

    @Autowired
    BrokerProperties properties;

    @Autowired
    ClientRepository clients;

    @Autowired
    UserRepository users;

    @Autowired
    SeedLoader seedLoader;

    @Autowired
    StringRedisTemplate redis;

    @Autowired
    SigningKey signingKey;

    @Autowired
    MockMvcTester mvc;

    @Test
    void bindsProperties() {
        assertThat(properties.issuer()).isEqualTo("https://localhost:8443");
        assertThat(properties.keystore().signingAlias()).isEqualTo("signing");
        assertThat(properties.ttl().authorizationCode()).isEqualTo(Duration.ofSeconds(60));
        assertThat(properties.ttl().refreshToken()).isEqualTo(Duration.ofDays(30));
    }

    @Test
    void seedsClientsAndUsersIntoRedis() {
        assertThat(clients.find("web-app")).get()
                .satisfies(c -> assertThat(c.tokenEndpointAuthMethod()).isEqualTo(AuthMethod.CLIENT_SECRET_BASIC));
        assertThat(clients.find("jwt-app")).get()
                .satisfies(c -> assertThat(c.jwks()).containsKey("keys"));
        assertThat(clients.find("spa-app")).get()
                .satisfies(c -> assertThat(c.tokenEndpointAuthMethod()).isEqualTo(AuthMethod.NONE));

        var bcrypt = new BCryptPasswordEncoder();
        assertThat(clients.find("web-app").orElseThrow().clientSecretHash()).satisfies(
                hash -> assertThat(bcrypt.matches("web-app-secret", hash)).isTrue());
        assertThat(users.find("alice").orElseThrow().passwordHash()).satisfies(
                hash -> assertThat(bcrypt.matches("wonderland", hash)).isTrue());
        assertThat(users.find("bob").orElseThrow().passwordHash()).satisfies(
                hash -> assertThat(bcrypt.matches("builder", hash)).isTrue());
    }

    @Test
    void seedingIsIdempotent() throws Exception {
        var before = redis.opsForValue().get("client:jwt-app");

        seedLoader.run(new DefaultApplicationArguments());

        assertThat(redis.opsForValue().get("client:jwt-app")).isEqualTo(before);
        assertThat(redis.getExpire("client:jwt-app")).isEqualTo(-1L);
    }

    @Test
    void servesDiscoveryDocument() {
        assertThat(mvc.get().uri("/.well-known/openid-configuration")).hasStatusOk()
                .bodyJson().extractingPath("$.jwks_uri").isEqualTo("https://localhost:8443/jwks");
    }

    @Test
    void servesKeystoreSigningKeyAsJwks() throws Exception {
        assertThat(signingKey.keyId()).isEqualTo(signingKey.jwk().computeThumbprint().toString());
        assertThat(mvc.get().uri("/jwks")).hasStatusOk()
                .bodyJson().extractingPath("$.keys[0].kid").isEqualTo(signingKey.keyId());
        assertThat(mvc.get().uri("/jwks")).bodyJson().doesNotHavePath("$.keys[0].d");
    }

    @Test
    void servesOpenApiDocs() {
        var docs = assertThat(mvc.get().uri("/v3/api-docs")).hasStatusOk().bodyJson();
        docs.extractingPath("$.openapi").asString().startsWith("3.");
        docs.extractingPath("$.servers[0].url").isEqualTo("https://localhost:8443");
        docs.hasPath("$.paths['/.well-known/openid-configuration'].get");
        docs.hasPath("$.paths['/jwks'].get");
        docs.hasPath("$.components.schemas.OpenIdConfiguration.properties.jwks_uri");
        docs.extractingPath("$.components.securitySchemes.clientSecretBasic.scheme").isEqualTo("basic");
        docs.extractingPath("$.components.securitySchemes.bearerAuth.scheme").isEqualTo("bearer");

        assertThat(mvc.get().uri("/v3/api-docs.yaml")).hasStatusOk()
                .bodyText().contains("/.well-known/openid-configuration");
    }

    @Test
    void documentsAuthorizationEndpoint() {
        var docs = assertThat(mvc.get().uri("/v3/api-docs")).hasStatusOk().bodyJson();
        docs.extractingPath("$.paths['/authorize'].get.parameters[*].name").asArray().contains(
                "response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge",
                "code_challenge_method");
        docs.hasPath("$.paths['/authorize'].get.responses['200'].content['text/html']");
        docs.hasPath("$.paths['/authorize'].get.responses['302'].headers.Location");
        docs.hasPath("$.paths['/authorize'].get.responses['400']");
        docs.hasPath("$.paths['/authorize'].post.requestBody.content['application/x-www-form-urlencoded']"
                + ".schema.properties.request_id");
        docs.hasPath("$.paths['/authorize'].post.responses['302']");
    }

    @Test
    void authorizesAndIssuesCodeThroughRedis() {
        var page = assertThat(mvc.get().uri("/authorize?response_type=code&client_id=spa-app"
                + "&redirect_uri=http://localhost:8080/callback&scope=openid&state=s1"
                + "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"))
                .hasStatusOk().bodyText().actual();
        var requestId = page.replaceAll("(?s).*name=\"request_id\" value=\"([^\"]+)\".*", "$1");

        var login = mvc.post().uri("/authorize").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .formField("request_id", requestId).formField("username", "alice").formField("password", "wonderland");
        var location = assertThat(login).hasStatus(302).actual().getResponse().getHeader("Location");
        assertThat(location).startsWith("http://localhost:8080/callback?code=")
                .endsWith("&state=s1&iss=https%3A%2F%2Flocalhost%3A8443");
        var code = location.replaceAll(".*code=([^&]+)&.*", "$1");
        assertThat(redis.getExpire("code:" + code)).isBetween(1L, 60L);

        assertThat(mvc.post().uri("/authorize").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .formField("request_id", requestId).formField("username", "alice").formField("password", "wonderland"))
                .hasStatus(400);
    }
}
