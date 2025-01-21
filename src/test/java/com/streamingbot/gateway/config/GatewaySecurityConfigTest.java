package com.streamingbot.gateway.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import java.time.Instant;
import java.util.Collections;
import java.util.Arrays;

@WebFluxTest
@Import({TestSecurityConfig.class, GatewaySecurityConfigTest.TestController.class})
class GatewaySecurityConfigTest {

    @RestController
    static class TestController {
        @GetMapping("/auth/something")
        public Mono<String> publicEndpoint() {
            return Mono.just("public");
        }

        @GetMapping("/api/protected")
        public Mono<String> protectedEndpoint() {
            return Mono.just("protected");
        }
    }

    @Autowired
    private WebTestClient webClient;

    @Autowired
    private org.springframework.web.cors.reactive.CorsConfigurationSource corsConfigurationSource;

    @MockBean
    private ReactiveJwtDecoder jwtDecoder;

    @BeforeEach
    void setUp() {
        Jwt jwt = Jwt.withTokenValue("valid_token")
            .header("alg", "RS256")
            .claim("sub", "user")
            .claim("scope", Arrays.asList("user"))
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(300))
            .build();

        when(jwtDecoder.decode("valid_token")).thenReturn(Mono.just(jwt));
    }

    @Test
    void corsConfigurationTest() {
        MockServerHttpRequest request = MockServerHttpRequest
            .get("http://localhost:8080")
            .header("Origin", "http://localhost:5000")
            .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        
        org.springframework.web.cors.CorsConfiguration corsConfig = 
            corsConfigurationSource.getCorsConfiguration(exchange);

        assertNotNull(corsConfig);
        assertTrue(corsConfig.getAllowedOrigins().contains("http://localhost:5000"));
        assertTrue(corsConfig.getAllowedMethods().contains("GET"));
        assertTrue(corsConfig.getAllowedMethods().contains("POST"));
        assertTrue(corsConfig.getAllowedHeaders().contains("Authorization"));
        assertTrue(corsConfig.getAllowCredentials());
    }

    @Test
    void testPublicEndpointsAccessible() {
        webClient
            .get()
            .uri("/auth/something")
            .exchange()
            .expectStatus().isOk()
            .expectBody(String.class)
            .isEqualTo("public");
    }

    @Test
    void testAuthenticatedUserCanAccessProtectedEndpoints() {
        webClient
            .get()
            .uri("/api/protected")
            .headers(headers -> headers.setBearerAuth("valid_token"))
            .exchange()
            .expectStatus().isOk()
            .expectBody(String.class)
            .isEqualTo("protected");
    }
} 