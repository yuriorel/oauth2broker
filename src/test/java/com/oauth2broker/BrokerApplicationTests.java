package com.oauth2broker;

import static org.assertj.core.api.Assertions.assertThat;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jwt.SignedJWT;
import com.oauth2broker.client.AuthMethod;
import com.oauth2broker.client.ClientCredentials;
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

    @Test
    void documentsTokenEndpoint() {
        var docs = assertThat(mvc.get().uri("/v3/api-docs")).hasStatusOk().bodyJson();
        var token = "$.paths['/token'].post";
        docs.extractingPath(token + ".requestBody.content['application/x-www-form-urlencoded'].schema.properties")
                .asMap().containsKeys("grant_type", "code", "redirect_uri", "code_verifier", "refresh_token", "scope",
                        "client_id", "client_assertion_type", "client_assertion");
        docs.hasPath(token + ".security[0].clientSecretBasic");
        docs.extractingPath(token + ".responses['200'].content['application/json'].schema.$ref")
                .isEqualTo("#/components/schemas/TokenResponse");
        docs.extractingPath(token + ".responses['401'].content['application/json'].schema.$ref")
                .isEqualTo("#/components/schemas/ErrorResponse");
        docs.hasPath("$.components.schemas.TokenResponse.properties.id_token");
        docs.hasPath("$.components.schemas.ErrorResponse.properties.error_description");
    }

    @Test
    void publicClientRedeemsCodeAndRotatesRefreshToken() {
        var tokens = tokenRequest(null).formField("grant_type", "authorization_code").formField("code", code("spa-app"))
                .formField("redirect_uri", CALLBACK).formField("code_verifier", VERIFIER)
                .formField("client_id", "spa-app");
        var body = assertThat(tokens).hasStatusOk().hasHeader("Cache-Control", "no-store").bodyText().actual();
        String refreshToken = JsonPath.read(body, "$.refresh_token");
        String jti = jti(JsonPath.read(body, "$.access_token"));
        assertThat(redis.getExpire("at:" + jti)).isBetween(1L, 900L);
        assertThat((String) JsonPath.read(body, "$.id_token")).isNotBlank();

        var refreshed = assertThat(tokenRequest(null).formField("grant_type", "refresh_token")
                .formField("refresh_token", refreshToken).formField("client_id", "spa-app"))
                .hasStatusOk().bodyText().actual();
        assertThat((String) JsonPath.read(refreshed, "$.refresh_token")).isNotEqualTo(refreshToken);

        assertThat(tokenRequest(null).formField("grant_type", "refresh_token")
                .formField("refresh_token", refreshToken).formField("client_id", "spa-app"))
                .hasStatus(400).bodyJson().extractingPath("$.error").isEqualTo("invalid_grant");
    }

    @Test
    void confidentialClientUsesBasicAndCodeIsSingleUse() {
        var code = code("web-app");
        var basic = "Basic " + Base64.getEncoder().encodeToString("web-app:web-app-secret".getBytes());

        assertThat(tokenRequest(basic).formField("grant_type", "authorization_code").formField("code", code)
                .formField("redirect_uri", CALLBACK).formField("code_verifier", VERIFIER)).hasStatusOk();
        assertThat(tokenRequest(basic).formField("grant_type", "authorization_code").formField("code", code)
                .formField("redirect_uri", CALLBACK).formField("code_verifier", VERIFIER))
                .hasStatus(400).bodyJson().extractingPath("$.error").isEqualTo("invalid_grant");

        var wrongSecret = "Basic " + Base64.getEncoder().encodeToString("web-app:nope".getBytes());
        assertThat(tokenRequest(wrongSecret).formField("grant_type", "authorization_code")
                .formField("code", code("web-app")).formField("redirect_uri", CALLBACK)
                .formField("code_verifier", VERIFIER)).hasStatus(401);
    }

    @Test
    void privateKeyJwtClientAuthenticatesWithAssertionOnlyOnce() {
        var assertion = ClientAssertions.sign(ClientAssertions.claims(Instant.now()).build());

        assertThat(tokenRequest(null).formField("grant_type", "authorization_code").formField("code", code("jwt-app"))
                .formField("redirect_uri", CALLBACK).formField("code_verifier", VERIFIER)
                .formField("client_assertion_type", ClientCredentials.JWT_BEARER)
                .formField("client_assertion", assertion)).hasStatusOk();
        assertThat(tokenRequest(null).formField("grant_type", "authorization_code").formField("code", code("jwt-app"))
                .formField("redirect_uri", CALLBACK).formField("code_verifier", VERIFIER)
                .formField("client_assertion_type", ClientCredentials.JWT_BEARER)
                .formField("client_assertion", assertion))
                .hasStatus(401).bodyJson().extractingPath("$.error_description")
                .isEqualTo("Assertion has already been used");
    }

    @Test
    void documentsRevocationEndpoint() {
        var docs = assertThat(mvc.get().uri("/v3/api-docs")).hasStatusOk().bodyJson();
        var revoke = "$.paths['/revoke'].post";
        docs.extractingPath(revoke + ".requestBody.content['application/x-www-form-urlencoded'].schema.properties")
                .asMap().containsKeys("token", "token_type_hint", "client_id", "client_assertion_type",
                        "client_assertion");
        docs.hasPath(revoke + ".security[0].clientSecretBasic");
        docs.hasPath(revoke + ".responses['200']");
        docs.extractingPath(revoke + ".responses['401'].content['application/json'].schema.$ref")
                .isEqualTo("#/components/schemas/ErrorResponse");
    }

    @Test
    void revokesOwnTokensButNotThoseOfAnotherClient() {
        var body = assertThat(tokenRequest(null).formField("grant_type", "authorization_code")
                .formField("code", code("spa-app")).formField("redirect_uri", CALLBACK)
                .formField("code_verifier", VERIFIER).formField("client_id", "spa-app"))
                .hasStatusOk().bodyText().actual();
        String accessToken = JsonPath.read(body, "$.access_token");
        String refreshToken = JsonPath.read(body, "$.refresh_token");
        var jti = jti(accessToken);
        var basic = "Basic " + Base64.getEncoder().encodeToString("web-app:web-app-secret".getBytes());

        assertThat(revokeRequest(basic).formField("token", accessToken)).hasStatusOk();
        assertThat(redis.hasKey("at:" + jti)).isTrue();

        assertThat(revokeRequest(null).formField("token", accessToken).formField("client_id", "spa-app"))
                .hasStatusOk();
        assertThat(redis.hasKey("at:" + jti)).isFalse();

        assertThat(revokeRequest(null).formField("token", refreshToken).formField("token_type_hint", "refresh_token")
                .formField("client_id", "spa-app")).hasStatusOk();
        assertThat(tokenRequest(null).formField("grant_type", "refresh_token").formField("refresh_token", refreshToken)
                .formField("client_id", "spa-app")).hasStatus(400);

        assertThat(revokeRequest(null).formField("token", refreshToken).formField("client_id", "spa-app"))
                .hasStatusOk();
    }

    @Test
    void documentsUserInfoEndpoint() {
        var docs = assertThat(mvc.get().uri("/v3/api-docs")).hasStatusOk().bodyJson();
        for (var method : new String[] {"get", "post"}) {
            var op = "$.paths['/userinfo']." + method;
            docs.hasPath(op + ".security[0].bearerAuth");
            docs.extractingPath(op + ".responses['200'].content['application/json'].schema.$ref")
                    .isEqualTo("#/components/schemas/UserInfo");
            docs.hasPath(op + ".responses['401'].headers.WWW-Authenticate");
            docs.hasPath(op + ".responses['403'].headers.WWW-Authenticate");
        }
        docs.hasPath("$.components.schemas.UserInfo.properties.email_verified");
    }

    @Test
    void userInfoReturnsScopedClaimsUntilTokenIsRevoked() {
        var body = assertThat(tokenRequest(null).formField("grant_type", "authorization_code")
                .formField("code", code("spa-app")).formField("redirect_uri", CALLBACK)
                .formField("code_verifier", VERIFIER).formField("client_id", "spa-app"))
                .hasStatusOk().bodyText().actual();
        var bearer = "Bearer " + JsonPath.read(body, "$.access_token");

        assertThat(mvc.get().uri("/userinfo").header("Authorization", bearer)).hasStatusOk()
                .bodyJson().isStrictlyEqualTo("""
                        {"sub": "alice", "name": "Alice Liddell"}
                        """);
        assertThat(mvc.post().uri("/userinfo").header("Authorization", bearer)).hasStatusOk();

        assertThat(revokeRequest(null).formField("token", bearer.substring(7)).formField("client_id", "spa-app"))
                .hasStatusOk();
        assertThat(mvc.get().uri("/userinfo").header("Authorization", bearer)).hasStatus(401)
                .hasHeader("WWW-Authenticate", "Bearer realm=\"oauth2broker\", error=\"invalid_token\", "
                        + "error_description=\"Access token has been revoked\"");
    }

    private MockMvcTester.MockMvcRequestBuilder revokeRequest(String authorization) {
        var request = mvc.post().uri("/revoke").contentType(MediaType.APPLICATION_FORM_URLENCODED);
        return authorization == null ? request : request.header("Authorization", authorization);
    }

    private static final String CALLBACK = "http://localhost:8080/callback";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    private MockMvcTester.MockMvcRequestBuilder tokenRequest(String authorization) {
        var request = mvc.post().uri("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED);
        return authorization == null ? request : request.header("Authorization", authorization);
    }

    /** Runs /authorize and the login form for alice, and returns the issued code. */
    private String code(String clientId) {
        var page = assertThat(mvc.get().uri("/authorize?response_type=code&client_id=" + clientId
                + "&redirect_uri=" + CALLBACK + "&scope=openid profile"
                + "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"))
                .hasStatusOk().bodyText().actual();
        var requestId = page.replaceAll("(?s).*name=\"request_id\" value=\"([^\"]+)\".*", "$1");
        var location = assertThat(mvc.post().uri("/authorize").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .formField("request_id", requestId).formField("username", "alice").formField("password", "wonderland"))
                .hasStatus(302).actual().getResponse().getHeader("Location");
        return location.replaceAll(".*code=([^&]+)&.*", "$1");
    }

    private static String jti(String jwt) {
        try {
            return SignedJWT.parse(jwt).getJWTClaimsSet().getJWTID();
        } catch (ParseException e) {
            throw new IllegalStateException(e);
        }
    }
}
