package com.oauth2broker.token;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.oauth2broker.client.ClientCredentials;
import com.oauth2broker.config.OpenApiConfig;
import com.oauth2broker.web.ErrorResponse;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@Tag(name = "Token", description = "Exchanges authorization codes and refresh tokens for tokens")
public class TokenController {

    private final TokenService service;

    public TokenController(TokenService service) {
        this.service = service;
    }

    @PostMapping(path = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Token request",
            description = "Grants: authorization_code (with PKCE) and refresh_token. Client authentication: "
                    + "client_secret_basic (HTTP Basic), private_key_jwt (client_assertion, RFC 7523) or none "
                    + "(client_id only, public clients). The method must match the client's registration.",
            security = @SecurityRequirement(name = OpenApiConfig.CLIENT_SECRET_BASIC))
    @ApiResponse(responseCode = "200", description = "Tokens issued",
            content = @Content(schema = @Schema(implementation = TokenResponse.class)))
    @ApiResponse(responseCode = "400", description = "invalid_request, invalid_grant, invalid_scope or unsupported_grant_type",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    @ApiResponse(responseCode = "401", description = "invalid_client",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<TokenResponse> token(
            @Parameter(hidden = true)
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @Parameter(description = "authorization_code or refresh_token", required = true)
            @RequestParam(name = "grant_type", required = false) String grantType,
            @Parameter(description = "Authorization code (authorization_code grant)")
            @RequestParam(required = false) String code,
            @Parameter(description = "Same redirect_uri as in the authorization request (authorization_code grant)")
            @RequestParam(name = "redirect_uri", required = false) String redirectUri,
            @Parameter(description = "PKCE code verifier (authorization_code grant)")
            @RequestParam(name = "code_verifier", required = false) String codeVerifier,
            @Parameter(description = "Refresh token (refresh_token grant)")
            @RequestParam(name = "refresh_token", required = false) String refreshToken,
            @Parameter(description = "Narrower scope for the new access token (refresh_token grant)")
            @RequestParam(required = false) String scope,
            @Parameter(description = "Client identifier: required for public clients, optional with client_assertion")
            @RequestParam(name = "client_id", required = false) String clientId,
            @Parameter(description = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer (private_key_jwt)")
            @RequestParam(name = "client_assertion_type", required = false) String clientAssertionType,
            @Parameter(description = "JWT signed with the client's registered key, RS256 or ES256 (private_key_jwt)")
            @RequestParam(name = "client_assertion", required = false) String clientAssertion) {
        var request = TokenRequest.of(grantType, code, redirectUri, codeVerifier, refreshToken, scope);
        var credentials = ClientCredentials.from(authorization, clientId, clientAssertionType, clientAssertion);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(service.token(request, credentials));
    }
}
