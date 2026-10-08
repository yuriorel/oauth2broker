package com.oauth2broker.authorize;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.oauth2broker.authorize.AuthorizeOutcome.ErrorPage;
import com.oauth2broker.authorize.AuthorizeOutcome.LoginPage;
import com.oauth2broker.authorize.AuthorizeOutcome.Redirect;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

@Controller
@Tag(name = "Authorization", description = "Authorization code flow with PKCE and the login form")
public class AuthorizationController {

    private final AuthorizationService service;

    public AuthorizationController(AuthorizationService service) {
        this.service = service;
    }

    @GetMapping(path = "/authorize", produces = MediaType.TEXT_HTML_VALUE)
    @Operation(summary = "Authorization request",
            description = "Validates the request and shows the login form. Errors in client_id or redirect_uri "
                    + "show an error page; other errors redirect to the client with error, state and iss.")
    @ApiResponse(responseCode = "200", description = "Login form",
            content = @Content(mediaType = MediaType.TEXT_HTML_VALUE, schema = @Schema(type = "string")))
    @ApiResponse(responseCode = "302", description = "Redirect to redirect_uri with error, error_description, state and iss",
            headers = @Header(name = "Location", schema = @Schema(type = "string", format = "uri")))
    @ApiResponse(responseCode = "400", description = "Unknown client or unregistered redirect_uri",
            content = @Content(mediaType = MediaType.TEXT_HTML_VALUE, schema = @Schema(type = "string")))
    public ResponseEntity<String> authorize(
            @Parameter(description = "Must be code", required = true, example = "code")
            @RequestParam(name = "response_type", required = false) String responseType,
            @Parameter(description = "Registered client identifier", required = true, example = "web-app")
            @RequestParam(name = "client_id", required = false) String clientId,
            @Parameter(description = "Exactly one of the client's registered redirect URIs", required = true,
                    example = "http://localhost:8080/callback")
            @RequestParam(name = "redirect_uri", required = false) String redirectUri,
            @Parameter(description = "Space-separated scopes allowed for the client", required = true,
                    example = "openid profile email")
            @RequestParam(required = false) String scope,
            @Parameter(description = "Opaque value returned unchanged in the redirect")
            @RequestParam(required = false) String state,
            @Parameter(description = "Value copied into the ID token")
            @RequestParam(required = false) String nonce,
            @Parameter(description = "PKCE challenge: base64url SHA-256 of the code verifier", required = true)
            @RequestParam(name = "code_challenge", required = false) String codeChallenge,
            @Parameter(description = "Must be S256", required = true, example = "S256")
            @RequestParam(name = "code_challenge_method", required = false) String codeChallengeMethod) {
        return respond(service.authorize(new AuthorizeParams(responseType, clientId, redirectUri, scope, state, nonce,
                codeChallenge, codeChallengeMethod)));
    }

    @PostMapping(path = "/authorize", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.TEXT_HTML_VALUE)
    @Operation(summary = "Login form submission",
            description = "Signs the user in for a pending request and redirects to the client with a single-use code.")
    @ApiResponse(responseCode = "200", description = "Login form again, after a wrong username or password",
            content = @Content(mediaType = MediaType.TEXT_HTML_VALUE, schema = @Schema(type = "string")))
    @ApiResponse(responseCode = "302", description = "Redirect to redirect_uri with code, state and iss",
            headers = @Header(name = "Location", schema = @Schema(type = "string", format = "uri")))
    @ApiResponse(responseCode = "400", description = "The pending request has expired or is unknown",
            content = @Content(mediaType = MediaType.TEXT_HTML_VALUE, schema = @Schema(type = "string")))
    public ResponseEntity<String> login(
            @Parameter(description = "Id of the pending request, from the login form", required = true)
            @RequestParam(name = "request_id", required = false) String requestId,
            @Parameter(description = "Username", required = true)
            @RequestParam(required = false) String username,
            @Parameter(description = "Password", required = true)
            @RequestParam(required = false) String password) {
        return respond(service.login(requestId, username, password));
    }

    private static ResponseEntity<String> respond(AuthorizeOutcome outcome) {
        return switch (outcome) {
            case LoginPage(var requestId, var clientId, var username, var error) ->
                    html(HttpStatus.OK, Pages.login(requestId, clientId, username, error));
            case Redirect(var location) -> ResponseEntity.status(HttpStatus.FOUND).location(location)
                    .cacheControl(CacheControl.noStore()).build();
            case ErrorPage(var message) -> html(HttpStatus.BAD_REQUEST, Pages.error(message));
        };
    }

    private static ResponseEntity<String> html(HttpStatus status, String body) {
        return ResponseEntity.status(status)
                .contentType(MediaType.TEXT_HTML)
                .cacheControl(CacheControl.noStore())
                .header("Content-Security-Policy", "frame-ancestors 'none'")
                .body(body);
    }
}
