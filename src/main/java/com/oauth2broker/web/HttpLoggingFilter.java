package com.oauth2broker.web;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/// At DEBUG, logs every request and response with headers and body, raw and unmasked, so the log file may hold
/// passwords, secrets and tokens. Runs right after [RequestIdFilter], so both lines carry the request id. At any
/// other level the request passes through unwrapped.
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 2)
public class HttpLoggingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(HttpLoggingFilter.class);
    private static final int MAX_CACHED_REQUEST_BODY = 1024 * 1024;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        var path = request.getRequestURI();
        return !log.isDebugEnabled() || path.startsWith("/v3/api-docs") || path.startsWith("/swagger-ui");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        var cachedRequest = new ContentCachingRequestWrapper(request, MAX_CACHED_REQUEST_BODY);
        var cachedResponse = new ContentCachingResponseWrapper(response);
        var start = System.nanoTime();
        try {
            chain.doFilter(cachedRequest, cachedResponse);
        } catch (ServletException | IOException | RuntimeException e) {
            logRequest(cachedRequest);
            log.debug("[{}] Request failed after {} ms", RequestContext.id(), millisSince(start), e);
            throw e;
        }
        logRequest(cachedRequest);
        log.debug("[{}] Response {} in {} ms headers={} body={}", RequestContext.id(), cachedResponse.getStatus(),
                millisSince(start), headers(cachedResponse.getHeaderNames(), cachedResponse::getHeaders),
                new String(cachedResponse.getContentAsByteArray(),
                        Charset.forName(cachedResponse.getCharacterEncoding())));
        cachedResponse.copyBodyToResponse();
    }

    /// Logged after the chain, because the request body is cached only once the controller has read it.
    private static void logRequest(ContentCachingRequestWrapper request) {
        var query = request.getQueryString() == null ? "" : "?" + request.getQueryString();
        log.debug("[{}] Request {} {}{} headers={} body={}", RequestContext.id(), request.getMethod(),
                request.getRequestURI(), query,
                headers(Collections.list(request.getHeaderNames()),
                        name -> Collections.list(request.getHeaders(name))),
                request.getContentAsString());
    }

    private static Map<String, Collection<String>> headers(Collection<String> names,
                                                           Function<String, Collection<String>> values) {
        var headers = new LinkedHashMap<String, Collection<String>>();
        names.forEach(name -> headers.put(name, values.apply(name)));
        return headers;
    }

    private static long millisSince(long start) {
        return (System.nanoTime() - start) / 1_000_000;
    }
}
