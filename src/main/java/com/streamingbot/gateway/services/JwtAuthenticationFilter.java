package com.streamingbot.gateway.services;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Map;

@Component
public class JwtAuthenticationFilter implements WebFilter {

    private final ReactiveJwtDecoder jwtDecoder;

    public JwtAuthenticationFilter(ReactiveJwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // Pass pre-flight requests
        if (exchange.getRequest().getMethod() == HttpMethod.OPTIONS) {
            return chain.filter(exchange);
        }

        String path = exchange.getRequest().getURI().getPath();
        System.out.println("Processing request for path: " + path);

        // Skip auth for login/register
        if (path.startsWith("/auth/login") || path.startsWith("/auth/register")) {
            return chain.filter(exchange);
        }

        String authorizationHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        System.out.println("Authorization header present: " + (authorizationHeader != null));

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String jwtToken = authorizationHeader.substring(7);
            System.out.println("Attempting to decode JWT token");

            return jwtDecoder.decode(jwtToken)
                .map(jwt -> {
                    System.out.println("JWT decoded successfully");
                    System.out.println("JWT issuer: " + jwt.getIssuer());

                    Map<String, Object> realmAccess = jwt.getClaim("realm_access");
                    Collection<GrantedAuthority> authorities = RoleConverter.convertRealmRoles(realmAccess);

                    Authentication authentication = new JwtAuthenticationToken(jwt, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    System.out.println("Authentication set in SecurityContext");
                    
                    return jwt;
                })
                .then(chain.filter(exchange))
                .onErrorResume(e -> {
                    System.err.println("JWT validation failed: " + e.getMessage());
                    e.printStackTrace();
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                });
        } else {
            System.out.println("No valid Authorization header found");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }
}
