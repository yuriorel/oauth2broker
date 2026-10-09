package com.oauth2broker.web;

/** An OAuth error response (RFC 6749 section 5.2). Each subclass is one error code. */
public abstract sealed class OAuthException extends RuntimeException {

    private final String error;

    /**
     * {@code error_description} may contain only printable ASCII without {@code "} and {@code \} (RFC 6749 section
     * 5.2), so any other character is replaced before the message is set.
     */
    protected OAuthException(String error, String description) {
        var normalized = description.replaceAll("[^\\x20-\\x21\\x23-\\x5B\\x5D-\\x7E]", "?");
        this.error = error;
        super(normalized);
    }

    public String error() {
        return error;
    }

    public static final class InvalidRequest extends OAuthException {
        public InvalidRequest(String description) {
            super("invalid_request", description);
        }
    }

    public static final class InvalidClient extends OAuthException {
        public InvalidClient(String description) {
            super("invalid_client", description);
        }
    }

    public static final class InvalidGrant extends OAuthException {
        public InvalidGrant(String description) {
            super("invalid_grant", description);
        }
    }

    public static final class InvalidScope extends OAuthException {
        public InvalidScope(String description) {
            super("invalid_scope", description);
        }
    }

    /** Missing, malformed, expired or revoked bearer token (RFC 6750 section 3.1). */
    public static final class InvalidToken extends OAuthException {
        public InvalidToken(String description) {
            super("invalid_token", description);
        }
    }

    public static final class InsufficientScope extends OAuthException {
        public InsufficientScope(String description) {
            super("insufficient_scope", description);
        }
    }

    public static final class UnsupportedGrantType extends OAuthException {
        public UnsupportedGrantType(String description) {
            super("unsupported_grant_type", description);
        }
    }
}
