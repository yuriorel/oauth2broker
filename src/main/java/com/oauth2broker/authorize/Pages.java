package com.oauth2broker.authorize;

import static org.springframework.web.util.HtmlUtils.htmlEscape;

/** The HTML pages of the authorization endpoint. Every inserted value is HTML-escaped. */
final class Pages {

    private static final String LAYOUT = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <title>%s</title>
              <style>
                body { font-family: system-ui, sans-serif; max-width: 22rem; margin: 4rem auto; padding: 0 1rem; }
                label, input, button { display: block; width: 100%%; box-sizing: border-box; }
                input { margin: .25rem 0 1rem; padding: .5rem; }
                button { padding: .6rem; }
                .error { color: #b00020; }
              </style>
            </head>
            <body>
            %s
            </body>
            </html>
            """;

    private static final String LOGIN = """
            <h1>Sign in</h1>
            <p>to continue to <strong>%s</strong></p>
            %s
            <form method="post" action="/authorize">
              <input type="hidden" name="request_id" value="%s">
              <label for="username">Username</label>
              <input id="username" name="username" value="%s" autocomplete="username" required autofocus>
              <label for="password">Password</label>
              <input id="password" name="password" type="password" autocomplete="current-password" required>
              <button type="submit">Sign in</button>
            </form>
            """;

    private static final String ERROR = """
            <h1>Authorization error</h1>
            <p class="error">%s</p>
            """;

    private Pages() {
    }

    static String login(String requestId, String clientId, String username, String error) {
        var errorLine = error == null ? "" : "<p class=\"error\" role=\"alert\">%s</p>".formatted(htmlEscape(error));
        return LAYOUT.formatted("Sign in", LOGIN.formatted(htmlEscape(clientId), errorLine, htmlEscape(requestId),
                username == null ? "" : htmlEscape(username)));
    }

    static String error(String message) {
        return LAYOUT.formatted("Authorization error", ERROR.formatted(htmlEscape(message)));
    }
}
