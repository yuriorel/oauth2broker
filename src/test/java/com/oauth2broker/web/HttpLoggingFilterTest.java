package com.oauth2broker.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import com.oauth2broker.LogCapture;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

class HttpLoggingFilterTest {

    private static final String BODY = """
            {"access_token":"eyJ.a.b"}""";

    /// Reads the form parameter like a controller and writes a JSON body; records the request and response it saw.
    private static final class TokenServlet extends HttpServlet {

        HttpServletRequest seenRequest;
        HttpServletResponse seenResponse;

        @Override
        protected void service(HttpServletRequest request, HttpServletResponse response) throws IOException {
            seenRequest = request;
            seenResponse = response;
            assertThat(request.getParameter("grant_type")).isEqualTo("authorization_code");
            response.setContentType("application/json");
            response.setHeader("Cache-Control", "no-store");
            response.getWriter().write(BODY);
        }
    }

    private static MockHttpServletRequest tokenRequest() {
        var request = new MockHttpServletRequest("POST", "/token");
        request.setQueryString("debug=1");
        request.setContentType("application/x-www-form-urlencoded");
        request.addHeader("Authorization", "Basic d2ViLWFwcDp3ZWItYXBwLXNlY3JldA==");
        request.setContent("grant_type=authorization_code&code=abc".getBytes(StandardCharsets.UTF_8));
        request.addParameter("grant_type", "authorization_code");
        request.addParameter("code", "abc");
        return request;
    }

    @Test
    void debugLogsRequestAndResponseRawWithTheRequestId() throws Exception {
        var servlet = new TokenServlet();
        var response = new MockHttpServletResponse();
        try (var logs = LogCapture.debug(HttpLoggingFilter.class)) {
            new MockFilterChain(servlet, new RequestIdFilter(), new HttpLoggingFilter())
                    .doFilter(tokenRequest(), response);

            var id = "[" + response.getHeader(RequestIdFilter.REQUEST_ID) + "]";
            assertThat(logs.debugMessages()).hasSize(2);
            assertThat(logs.debugMessages().getFirst()).startsWith(id + " Request POST /token?debug=1")
                    .contains("Basic d2ViLWFwcDp3ZWItYXBwLXNlY3JldA==")
                    .endsWith("body=grant_type=authorization_code&code=abc");
            assertThat(logs.debugMessages().getLast()).startsWith(id + " Response 200 in ")
                    .contains("Cache-Control=[no-store]")
                    .endsWith("body=" + BODY);
        }
        assertThat(response.getContentAsString()).isEqualTo(BODY);
    }

    @Test
    void infoLeavesTheRequestUnwrappedAndLogsNothing() throws Exception {
        var servlet = new TokenServlet();
        var response = new MockHttpServletResponse();
        try (var logs = LogCapture.info(HttpLoggingFilter.class)) {
            new MockFilterChain(servlet, new HttpLoggingFilter()).doFilter(tokenRequest(), response);

            assertThat(logs.events()).isEmpty();
        }
        assertThat(servlet.seenRequest).isNotInstanceOf(ContentCachingRequestWrapper.class);
        assertThat(servlet.seenResponse).isNotInstanceOf(ContentCachingResponseWrapper.class);
        assertThat(response.getContentAsString()).isEqualTo(BODY);
    }

    @Test
    void apiDocsAreNotLogged() throws Exception {
        try (var logs = LogCapture.debug(HttpLoggingFilter.class)) {
            new HttpLoggingFilter().doFilter(new MockHttpServletRequest("GET", "/v3/api-docs"),
                    new MockHttpServletResponse(), new MockFilterChain());
            new HttpLoggingFilter().doFilter(new MockHttpServletRequest("GET", "/swagger-ui/index.html"),
                    new MockHttpServletResponse(), new MockFilterChain());

            assertThat(logs.events()).isEmpty();
        }
    }

    @Test
    void failedRequestIsLoggedWithTheException() {
        var servlet = new HttpServlet() {
            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response) {
                throw new IllegalStateException("boom");
            }
        };
        try (var logs = LogCapture.debug(HttpLoggingFilter.class)) {
            assertThatThrownBy(() -> new MockFilterChain(servlet, new HttpLoggingFilter())
                    .doFilter(tokenRequest(), new MockHttpServletResponse()))
                    .isInstanceOf(IllegalStateException.class);

            assertThat(logs.debugMessages().getFirst()).startsWith("[-] Request POST /token");
            assertThat(logs.events().getLast().getFormattedMessage()).startsWith("[-] Request failed after ");
            assertThat(logs.events().getLast().getThrowableProxy().getMessage()).isEqualTo("boom");
        }
    }
}
