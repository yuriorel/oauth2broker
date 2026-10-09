package com.oauth2broker.authorize;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.regex.Pattern;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import com.oauth2broker.authorize.AuthorizeOutcome.ErrorPage;
import com.oauth2broker.authorize.AuthorizeOutcome.LoginPage;
import com.oauth2broker.authorize.AuthorizeOutcome.Redirect;
import com.oauth2broker.client.ClientRegistration;
import com.oauth2broker.client.ClientRepository;
import com.oauth2broker.config.BrokerProperties;
import com.oauth2broker.user.UserRepository;
import com.oauth2broker.web.Scopes;

/** Validates authorization requests, signs users in and issues authorization codes. */
@Service
public class AuthorizationService {

    /** An S256 challenge is the base64url SHA-256 of the verifier: 43 characters, no padding. */
    private static final Pattern S256_CHALLENGE = Pattern.compile("[A-Za-z0-9_-]{43}");

    private final ClientRepository clients;
    private final UserRepository users;
    private final AuthorizationRequestRepository requests;
    private final AuthorizationCodeRepository codes;
    private final PasswordEncoder passwords;
    private final String issuer;
    private final Clock clock;

    public AuthorizationService(ClientRepository clients, UserRepository users,
                                AuthorizationRequestRepository requests, AuthorizationCodeRepository codes,
                                PasswordEncoder passwords, BrokerProperties properties, Clock clock) {
        this.clients = clients;
        this.users = users;
        this.requests = requests;
        this.codes = codes;
        this.passwords = passwords;
        this.issuer = properties.issuer();
        this.clock = clock;
    }

    /**
     * Checks the request. An unknown client or an unregistered redirect URI gives an error page, because
     * redirecting there would be unsafe; every other error is sent back to the client.
     */
    public AuthorizeOutcome authorize(AuthorizeParams params) {
        var client = params.clientId() == null ? null : clients.find(params.clientId()).orElse(null);
        if (client == null) {
            return new ErrorPage("Unknown client.");
        }
        if (params.redirectUri() == null || !client.redirectUris().contains(params.redirectUri())) {
            return new ErrorPage("The redirect URI is not registered for this client.");
        }
        var problem = problem(params, client);
        if (problem != null) {
            return redirect(params.redirectUri(), params.state(),
                    "error", problem.error(), "error_description", problem.description());
        }
        var request = new AuthorizationRequest(client.clientId(), params.redirectUri(), Scopes.parse(params.scope()),
                params.state(), params.nonce(), params.codeChallenge());
        return new LoginPage(requests.save(request), client.clientId(), null, null);
    }

    /** Signs the user in for a stored request and, on success, redirects back with a single-use code. */
    public AuthorizeOutcome login(String requestId, String username, String password) {
        var request = requestId == null ? null : requests.find(requestId).orElse(null);
        if (request == null) {
            return new ErrorPage("The sign-in request has expired or is unknown. Start again from the application.");
        }
        var user = username == null ? null : users.find(username).orElse(null);
        if (user == null || password == null || !passwords.matches(password, user.passwordHash())) {
            return new LoginPage(requestId, request.clientId(), username, "Invalid username or password.");
        }
        if (requests.take(requestId).isEmpty()) {
            return new ErrorPage("The sign-in request has already been used.");
        }
        var code = codes.save(new AuthorizationCode(request.clientId(), request.redirectUri(), user.username(),
                request.scope(), request.nonce(), request.codeChallenge(), clock.instant()));
        return redirect(request.redirectUri(), request.state(), "code", code);
    }

    private record Problem(String error, String description) {
    }

    private static Problem problem(AuthorizeParams params, ClientRegistration client) {
        if (params.responseType() == null) {
            return new Problem("invalid_request", "response_type is required");
        }
        if (!params.responseType().equals("code")) {
            return new Problem("unsupported_response_type", "Only response_type=code is supported");
        }
        if (params.scope() == null || params.scope().isBlank()) {
            return new Problem("invalid_scope", "scope is required");
        }
        if (!client.scopes().containsAll(Scopes.parse(params.scope()))) {
            return new Problem("invalid_scope", "scope contains values not allowed for this client");
        }
        if (params.codeChallenge() == null) {
            return new Problem("invalid_request", "code_challenge is required");
        }
        if (!"S256".equals(params.codeChallengeMethod())) {
            return new Problem("invalid_request", "code_challenge_method must be S256");
        }
        if (!S256_CHALLENGE.matcher(params.codeChallenge()).matches()) {
            return new Problem("invalid_request", "code_challenge is not a valid S256 challenge");
        }
        return null;
    }

    /** Redirects to {@code redirectUri} with the given name/value pairs, then {@code state} and {@code iss} (RFC 9207). */
    private Redirect redirect(String redirectUri, String state, String... pairs) {
        var uri = UriComponentsBuilder.fromUriString(redirectUri);
        for (var i = 0; i < pairs.length; i += 2) {
            uri.queryParam(pairs[i], encode(pairs[i + 1]));
        }
        if (state != null) {
            uri.queryParam("state", encode(state));
        }
        uri.queryParam("iss", encode(issuer));
        return new Redirect(uri.build(true).toUri());
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
