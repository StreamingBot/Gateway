package com.streamingbot.gateway.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import reactor.core.publisher.Mono;

@TestConfiguration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class TestSecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
            .csrf().disable()
            .authorizeExchange()
            .pathMatchers("/auth/**").permitAll()
            .pathMatchers("/api/protected").hasAuthority("SCOPE_user")
            .anyExchange().authenticated()
            .and()
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(token -> {
                        if (token.getTokenValue().equals("invalid_token")) {
                            return Mono.error(new RuntimeException("Invalid token"));
                        }
                        return Mono.just(new JwtAuthenticationToken(token));
                    })
                )
            )
            .httpBasic().disable()
            .formLogin().disable()
            .build();
    }
} 