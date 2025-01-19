package com.streamingbot.gateway.services;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
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

    private final JwtDecoder jwtDecoder;

    public JwtAuthenticationFilter(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // Pass pre-flight requests
        if (exchange.getRequest().getMethod() == HttpMethod.OPTIONS) {
            return chain.filter(exchange);  // Let the request pass without auth check
        }


        // Skip the filter for the /identity/login endpoint
        System.out.println(exchange.getRequest().getURI().getPath());
        if (exchange.getRequest().getURI().getPath().startsWith("/auth/login") || exchange.getRequest().getURI().getPath().startsWith("/auth/register")) {
            return chain.filter(exchange); // Skip further processing for login endpoint
        }

        String authorizationHeader = exchange.getRequest().getHeaders().getFirst("Authorization");

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String jwtToken = authorizationHeader.substring(7);
            System.out.println(authorizationHeader);

            try {
                Jwt decodedJwt = jwtDecoder.decode(jwtToken);

                // Extract roles from the JWT claims
                Map<String, Object> realmAccess = decodedJwt.getClaim("realm_access");
                Collection<GrantedAuthority> authorities = RoleConverter.convertRealmRoles(realmAccess);

                // Create Authentication object and set it in the SecurityContext
                Authentication authentication = new JwtAuthenticationToken(decodedJwt, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);

            } catch (JwtException e) {
                // Handle invalid JWT or token validation failure
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
        }
        else
        {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        return chain.filter(exchange); // Proceed with the chain of filters
    }
}
