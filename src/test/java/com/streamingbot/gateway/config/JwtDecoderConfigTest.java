package com.streamingbot.gateway.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@SpringBootTest
@Import(JwtDecoderTestConfig.class)
class JwtDecoderConfigTest {

    @Autowired
    private JwtDecoder jwtDecoder;

    @Test
    void jwtDecoderIsConfigured() {
        assertNotNull(jwtDecoder);
    }
} 