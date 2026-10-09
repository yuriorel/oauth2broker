package com.oauth2broker.userinfo;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import com.oauth2broker.config.OpenApiConfig;
import com.oauth2broker.web.ErrorResponse;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@Tag(name = "UserInfo", description = "Claims about the signed-in user (OpenID Connect Core 5.3)")
public class UserInfoController {

    private final UserInfoService service;

    public UserInfoController(UserInfoService service) {
        this.service = service;
    }

    /** OpenAPI description shared by the GET and POST operations. */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @ApiResponse(responseCode = "200", description = "sub, plus name (profile scope) and email, email_verified (email scope)",
            content = @Content(schema = @Schema(implementation = UserInfo.class)))
    @ApiResponse(responseCode = "401", description = "invalid_token: missing, malformed, expired or revoked access token",
            headers = @Header(name = HttpHeaders.WWW_AUTHENTICATE, schema = @Schema(type = "string")),
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    @ApiResponse(responseCode = "403", description = "insufficient_scope: the access token lacks the openid scope",
            headers = @Header(name = HttpHeaders.WWW_AUTHENTICATE, schema = @Schema(type = "string")),
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    @interface UserInfoResponses {
    }

    @GetMapping(path = "/userinfo", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "UserInfo", description = "Returns the claims allowed by the access token's scope.",
            security = @SecurityRequirement(name = OpenApiConfig.BEARER_AUTH))
    @UserInfoResponses
    public ResponseEntity<UserInfo> get(@Parameter(hidden = true)
                                        @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        return respond(authorization);
    }

    @PostMapping(path = "/userinfo", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "UserInfo (POST)", description = "Same as GET; the access token is sent in the Authorization header.",
            security = @SecurityRequirement(name = OpenApiConfig.BEARER_AUTH))
    @UserInfoResponses
    public ResponseEntity<UserInfo> post(@Parameter(hidden = true)
                                         @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        return respond(authorization);
    }

    private ResponseEntity<UserInfo> respond(String authorization) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(service.userInfo(authorization));
    }
}
