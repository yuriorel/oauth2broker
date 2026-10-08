package com.oauth2broker.authorize;

import java.net.URI;

/** What the authorization endpoint answers with. */
public sealed interface AuthorizeOutcome {

    /** Show the login form for a stored request, with an optional error and the username to fill in again. */
    record LoginPage(String requestId, String clientId, String username, String error) implements AuthorizeOutcome {
    }

    /** Send the browser back to the client, with a code or an error. */
    record Redirect(URI location) implements AuthorizeOutcome {
    }

    /** The client or redirect URI cannot be trusted, so the error is shown to the user instead. */
    record ErrorPage(String message) implements AuthorizeOutcome {
    }
}
