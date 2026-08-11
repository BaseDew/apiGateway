package com.basedew.api_gateway.security;

import org.jspecify.annotations.NonNull;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class PathIdentityValidationFilter implements GlobalFilter, Ordered {
    private final JwtService jwtService;
    private final Pattern userPathPattern = Pattern.compile("^/api/[^/]+/[^/]+/(\\d+)(?:/|$)");

    public PathIdentityValidationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    @NonNull
    public Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        Matcher matcher = userPathPattern.matcher(path);

        if (!matcher.find()) {
            return chain.filter(exchange);
        }

        String idFromPath = matcher.group(1);
        String token = extractToken(exchange);

        if (token == null) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        try {
            Object userIdClaim = jwtService.extractClaim(token, claims -> claims.get("userId"));
            if (userIdClaim == null) {
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }

            String idFromJwt = userIdClaim.toString();

            if (!idFromPath.equals(idFromJwt)) {
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }

        } catch (Exception e) {
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return exchange.getResponse().setComplete();
        }

        return chain.filter(exchange);
    }

    private String extractToken(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7).trim();
        }
        return null;
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
