package com.streamingbot.gateway.config;

import com.streamingbot.gateway.services.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import java.util.Collections;

@Configuration
public class GatewaySecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public GatewaySecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) throws Exception {
        http
                .csrf()
                .disable()
                .authorizeExchange()
                .pathMatchers(HttpMethod.OPTIONS).permitAll()
                .pathMatchers("/auth/**").permitAll()
                .anyExchange().authenticated()
                .and()
                .cors().configurationSource(corsConfigurationSource())
                .and()
                .oauth2ResourceServer()
                .jwt();

        http.addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.FIRST);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfig = new CorsConfiguration();
        // corsConfig.addAllowedOrigin("http://localhost:5000");
        corsConfig.addAllowedOrigin("*");
        corsConfig.addAllowedOrigin("http://host.docker.internal:5000");
        corsConfig.addAllowedOrigin("http://0.0.0.0:5000");
        corsConfig.addAllowedOrigin("http://127.0.0.1:5000");
        corsConfig.addAllowedOrigin("http://localhost:5000");
        corsConfig.addAllowedOrigin("http://gateway:5000");
        //corsConfig.setAllowedOriginPatterns(Collections.singletonList("*"));

        //add all methods
        corsConfig.addAllowedMethod("OPTIONS");
        corsConfig.addAllowedMethod("POST");
        corsConfig.addAllowedMethod("PUT");
        corsConfig.addAllowedMethod("DELETE");
        corsConfig.addAllowedMethod("GET");

        corsConfig.addAllowedMethod("*");
        corsConfig.addAllowedHeader("*");
        corsConfig.setAllowCredentials(true);

        corsConfig.addExposedHeader("Cache-Control");
        corsConfig.addExposedHeader("Pragma");
        corsConfig.addExposedHeader("Expires");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);

        return source;
    }

}
