package com.swift.microgateway.swift_microgateway.configuration;

import com.swift.microgateway.swift_microgateway.security.JwtUtil;
import com.swift.microgateway.swift_microgateway.security.SecurityCredentialService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

@Component
public class AccessTokenFilter implements GlobalFilter, Ordered {
    Logger logger = LoggerFactory.getLogger(AccessTokenFilter.class);

    @Autowired
    SecurityCredentialService securityCredentialService;
    @Autowired
    JwtUtil  jwtUtil;

    @Override
    public int getOrder() {
        return -1; // High priority execution
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String accessToken = exchange.getRequest().getHeaders().getFirst("X-Access-Token");
        logger.info("Access Token: " + accessToken);

        return DataBufferUtils.join(exchange.getRequest().getBody())
                .flatMap(dataBuffer -> {
                    byte[] requestBodyBytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(requestBodyBytes);
                    DataBufferUtils.release(dataBuffer); // Release buffer
                    logger.info("success 1");

                    String jwt = getJwt(requestBodyBytes, exchange.getRequest().getURI().toString());
                    logger.info("jwt : "+jwt);
                    // Restore the request body for downstream services
                    DataBufferFactory bufferFactory = exchange.getResponse().bufferFactory();
                    DataBuffer newDataBuffer = bufferFactory.wrap(requestBodyBytes);
                    Flux<DataBuffer> bodyFlux = Flux.just(newDataBuffer);

                    ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                            .header("Authorization", "Bearer " + accessToken)
                            .header("X-SWIFT-Signature",jwt)// Modify headers if needed
                            .build();

                    ServerHttpRequest decoratedRequest = new ServerHttpRequestDecorator(modifiedRequest) {
                        @Override
                        public Flux<DataBuffer> getBody() {
                            return bodyFlux; // Provide the restored body
                        }

                        @Override
                        public HttpHeaders getHeaders() {
                            HttpHeaders headers = new HttpHeaders();
                            headers.putAll(super.getHeaders());
                            headers.setContentLength(requestBodyBytes.length); // Ensure content-length is set correctly
                            return headers;
                        }
                    };

                    logger.info("success 5");

                    return chain.filter(exchange.mutate().request(decoratedRequest).build());
                });
    }

    private byte[] sha256Digest(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (Exception e) {
            throw new RuntimeException("Error computing SHA-256 digest", e);
        }
    }

    private String getJwt(byte[] requestBodyBytes,String audience) {
        try {
        String Server = Constants.PROTOCOL + Constants.SERVER;
        // Step 1: Encode request body in Base64
        String base64EncodedBody = Base64.getEncoder().encodeToString(requestBodyBytes);
        logger.info("success 2 : "+base64EncodedBody);

        // Step 2: Compute SHA-256 hash of Base64-encoded body
        byte[] digestBytes = sha256Digest(base64EncodedBody.getBytes(StandardCharsets.UTF_8));
        logger.info("success 3 : "+ digestBytes);

        // Step 3: Encode hash in Base64
        String base64EncodedDigest = Base64.getEncoder().encodeToString(digestBytes);
        logger.info("success 4 : "+base64EncodedDigest);

        CompletableFuture<SecurityCredentialService.SecurityCredentials> securityCredentialsCompletableFuture = securityCredentialService.fetchSecurityCredentials(Server);
        String key = securityCredentialsCompletableFuture.get().getPrivateKey();
        String certificate = securityCredentialsCompletableFuture.get().getCertificate();

        return jwtUtil.getJwtForNonRepudiation(certificate,key,audience,base64EncodedDigest);

        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }

    }
}
