package com.oauth2broker.it;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

import com.microsoft.playwright.APIRequest;
import com.microsoft.playwright.APIRequestContext;
import com.microsoft.playwright.APIResponse;
import com.microsoft.playwright.Browser;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.options.FormData;
import com.microsoft.playwright.options.RequestOptions;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.oauth2broker.client.ClientCredentials;
import com.oauth2broker.it.LoginPage.Callback;
import com.oauth2broker.it.TestClient.PrivateKeyJwt;
import com.oauth2broker.it.TestClient.Public;
import com.oauth2broker.it.TestClient.SecretBasic;
import com.sun.net.httpserver.HttpServer;

/**
 * The running broker, driven with Playwright: a headless Chromium for the login form and an API request context for
 * the token, revocation and userinfo endpoints. Both accept the self-signed certificate. The clients' redirect URI is
 * served by a local callback server, so the browser can follow the redirect after sign-in.
 */
final class Broker implements AutoCloseable {

    static final String BASE_URL = "https://localhost:8443";
    static final String REDIRECT_URI = "http://localhost:8080/callback";
    static final String SCOPE = "openid profile email";

    /** Parameters of one authorization request; {@code state} and {@code nonce} are random. */
    record Authorization(TestClient client, String redirectUri, Pkce pkce, String state, String nonce) {

        static Authorization of(TestClient client) {
            return new Authorization(client, REDIRECT_URI, Pkce.create(), UUID.randomUUID().toString(),
                    UUID.randomUUID().toString());
        }

        String url() {
            var query = new LinkedHashMap<String, String>();
            query.put("response_type", "code");
            query.put("client_id", client.id());
            query.put("redirect_uri", redirectUri);
            query.put("scope", SCOPE);
            query.put("state", state);
            query.put("nonce", nonce);
            query.put("code_challenge", pkce.challenge());
            query.put("code_challenge_method", "S256");
            return BASE_URL + "/authorize?" + query.entrySet().stream()
                    .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                    .collect(Collectors.joining("&"));
        }
    }

    private final HttpServer callback = callbackServer();
    private final Playwright playwright = Playwright.create();
    private final Browser browser = playwright.chromium().launch();
    private final APIRequestContext api = playwright.request().newContext(
            new APIRequest.NewContextOptions().setBaseURL(BASE_URL).setIgnoreHTTPSErrors(true));

    /** Answers {@link #REDIRECT_URI} with 200; each exchange runs on a virtual thread. */
    private static HttpServer callbackServer() {
        try {
            var server = HttpServer.create(new InetSocketAddress("localhost", 8080), 0);
            server.createContext("/callback", exchange -> {
                exchange.sendResponseHeaders(200, -1);
                exchange.close();
            });
            server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
            server.start();
            return server;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    LoginPage open(Authorization authorization) {
        return new LoginPage(browser, authorization.url());
    }

    /** Signs alice in through the login form and returns the redirect to the callback. */
    Callback signIn(Authorization authorization) {
        try (var page = open(authorization)) {
            return page.signIn("alice", "wonderland").callback();
        }
    }

    APIResponse redeem(Authorization authorization, String code) {
        return redeem(authorization.client(), code, authorization.pkce().verifier());
    }

    APIResponse redeem(TestClient client, String code, String verifier) {
        return post("/token", client, Map.of("grant_type", "authorization_code", "code", code,
                "redirect_uri", REDIRECT_URI, "code_verifier", verifier));
    }

    APIResponse refresh(TestClient client, String refreshToken) {
        return post("/token", client, Map.of("grant_type", "refresh_token", "refresh_token", refreshToken));
    }

    APIResponse revoke(TestClient client, String token) {
        return post("/revoke", client, Map.of("token", token));
    }

    APIResponse userInfo(String accessToken) {
        return api.get("/userinfo", RequestOptions.create().setHeader("Authorization", "Bearer " + accessToken));
    }

    APIResponse get(String path) {
        return api.get(path);
    }

    /** Posts the form with the client's authentication added. */
    private APIResponse post(String path, TestClient client, Map<String, String> params) {
        var form = FormData.create();
        params.forEach(form::set);
        var options = RequestOptions.create();
        switch (client) {
            case SecretBasic(var id, var secret) -> options.setHeader("Authorization", "Basic " + Base64.getEncoder()
                    .encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8)));
            case PrivateKeyJwt(_, var assertions) -> form.set("client_assertion_type", ClientCredentials.JWT_BEARER)
                    .set("client_assertion", assertions.get());
            case Public(var id) -> form.set("client_id", id);
        }
        return api.post(path, options.setForm(form));
    }

    static Map<String, Object> json(APIResponse response) {
        try {
            return JSONObjectUtils.parse(response.text());
        } catch (ParseException e) {
            throw new AssertionError("Not a JSON object: " + response.text(), e);
        }
    }

    /** Verifies the token's signature with the key from {@code /jwks} and returns its claims. */
    JWTClaimsSet verify(String token) {
        try {
            var jwt = SignedJWT.parse(token);
            var key = JWKSet.parse(get("/jwks").text()).getKeyByKeyId(jwt.getHeader().getKeyID()).toRSAKey();
            assertThat(jwt.verify(new RSASSAVerifier(key))).as("signature verifies with /jwks").isTrue();
            return jwt.getJWTClaimsSet();
        } catch (ParseException | JOSEException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    public void close() {
        api.dispose();
        playwright.close();
        callback.stop(0);
    }
}
