package com.streamingbot.gateway.config;

import com.streamingbot.gateway.services.JwtAuthenticationFilter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.TestPropertySource;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@WebFluxTest
@Import({GatewaySecurityConfig.class, TestSecurityConfig.class})
@TestPropertySource(properties = {
    "spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://localhost:8080/auth/realms/master/protocol/openid-connect/certs"
})
class GatewaySecurityConfigTest {

    @Autowired
    private GatewaySecurityConfig securityConfig;

    @MockBean
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @MockBean
    private ReactiveJwtDecoder jwtDecoder;

    @Test
    void corsConfigurationTest() {
        MockServerHttpRequest request = MockServerHttpRequest
            .get("http://localhost:8080")
            .header("Origin", "http://localhost:5000")
            .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        
        CorsConfigurationSource corsConfigurationSource = securityConfig.corsConfigurationSource();
        CorsConfiguration corsConfig = corsConfigurationSource.getCorsConfiguration(exchange);

        assertNotNull(corsConfig);
        assertTrue(corsConfig.getAllowedOrigins().contains("http://localhost:5000"));
        assertTrue(corsConfig.getAllowedMethods().contains("GET"));
        assertTrue(corsConfig.getAllowedMethods().contains("POST"));
        assertTrue(corsConfig.getAllowedHeaders().contains("*"));
        assertTrue(corsConfig.getAllowCredentials());
    }

    @Test
    void testPublicEndpointsAccessible(@Autowired WebTestClient webClient) {
        when(jwtAuthenticationFilter.filter(any(), any())).thenReturn(Mono.empty());

        webClient
                .options()
                .uri("/auth/something")
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    @WithMockUser
    void testAuthenticatedUserCanAccessProtectedEndpoints(@Autowired WebTestClient webClient) {
        when(jwtAuthenticationFilter.filter(any(), any())).thenReturn(Mono.empty());
        Jwt jwt = Jwt.withTokenValue("valid_token")
            .header("alg", "RS256")
            .claim("sub", "user")
            .claim("scope", "user")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(300))
            .build();
        when(jwtDecoder.decode(anyString())).thenReturn(Mono.just(jwt));

        webClient
                .get()
                .uri("/api/protected")
                .header("Authorization", "Bearer valid_token")
                .exchange()
                .expectStatus().isOk();
    }
} 