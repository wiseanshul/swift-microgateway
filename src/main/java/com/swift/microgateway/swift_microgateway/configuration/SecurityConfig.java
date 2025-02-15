package com.swift.microgateway.swift_microgateway.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                // Disable CSRF because this is a stateless API gateway
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                // Configure endpoint permissions
                .authorizeExchange(exchange -> exchange
                        .pathMatchers("/auth", "/refresh-token").permitAll()
                        .anyExchange().authenticated()
                )
                // Configure HTTP Basic authentication using the default settings
                .httpBasic(withDefaults())
                .build();



    }

}
