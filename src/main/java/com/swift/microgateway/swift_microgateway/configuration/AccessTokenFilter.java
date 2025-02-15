package com.swift.microgateway.swift_microgateway.configuration;


import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AccessTokenFilter implements GlobalFilter, Ordered {

    @Override
    public int getOrder() {
        // This filter executes first in the filter chain.
        return -1;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Extract the token from the "X-Access-Token" header.
        String accessToken = exchange.getRequest().getHeaders().getFirst("X-Access-Token");

        if (accessToken != null) {
            // Modify the request by adding the "Authorization" header.
            ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                    .header("Authorization", "Bearer " + accessToken)
                    .build();

            // Continue the filter chain with the modified request.
            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        }

        // If the token is not found, continue with the original request.
        return chain.filter(exchange);
    }
}

