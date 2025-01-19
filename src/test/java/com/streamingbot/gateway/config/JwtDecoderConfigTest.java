package com.streamingbot.gateway.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@TestPropertySource(properties = {
    "keycloak.auth-server-url=http://localhost:8080/auth",
    "keycloak.realm=master"
})
class JwtDecoderConfigTest {

    @Autowired
    private JwtDecoder jwtDecoder;

    @Test
    void jwtDecoderIsConfigured() {
        assertNotNull(jwtDecoder);
    }
} 