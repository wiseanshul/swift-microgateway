package com.swift.microgateway.swift_microgateway.configuration;

import com.swift.microgateway.swift_microgateway.common.AESEncryptionHelper;
import com.swift.microgateway.swift_microgateway.common.PropertiesService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

    @Autowired
    PropertiesService  propertiesService;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable) // Disable CSRF for API Gateway
                .authorizeExchange(exchange -> exchange
                                              .anyExchange().authenticated() // All Other Routes Require Authentication
                )
                .httpBasic(withDefaults()) // Enable Basic Auth
                .build();
    }

    @Bean
    public MapReactiveUserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
         final String username = propertiesService.getPropertyValue("external.gateway-user-name");
         final String password = AESEncryptionHelper.decrypt(propertiesService.getPropertyValue("external.gateway-secret"),propertiesService.getPropertyValue("external.gateway-secret-key"));

         UserDetails user = User.withUsername(username)
                .password(passwordEncoder.encode(password))  // Encode password
                .roles("USER")
                .build();

        return new MapReactiveUserDetailsService(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
