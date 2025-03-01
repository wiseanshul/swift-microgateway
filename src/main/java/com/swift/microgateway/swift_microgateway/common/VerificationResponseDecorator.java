package com.swift.microgateway.swift_microgateway.common;

import com.swift.microgateway.swift_microgateway.security.JwtUtil;
import org.reactivestreams.Publisher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

public class VerificationResponseDecorator extends ServerHttpResponseDecorator {

    @Autowired
    JwtUtil jwtUtil;

    private final ServerWebExchange exchange;

    public VerificationResponseDecorator(ServerHttpResponse delegate, ServerWebExchange exchange) {
        super(delegate);
        this.exchange = exchange;
    }

    @Override
    public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
        return DataBufferUtils.join(Flux.from(body))
                .flatMap(dataBuffer -> {
                    // Buffer the response body
                    byte[] responseBodyBytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(responseBodyBytes);
                    DataBufferUtils.release(dataBuffer);

                    // Compute digest (replace with your actual logic)
                    String computedDigest = computeSha256Digest(responseBodyBytes);

                    // Get and verify the JWT
                    String jwt = getHeaders().getFirst("X-SWIFT-Integrity");
                    if (jwt == null) {
                        return setErrorResponse(getDelegate(), "Missing X-SWIFT-Integrity header");
                    }

                    boolean isJwtValid = jwtUtil.verifyJwtSignatureAndExpiration(jwt);
                    String expectedDigest = jwtUtil.extractDigestFromJwt(jwt);
                    boolean isValid = isJwtValid && computedDigest.equals(expectedDigest);

                    if (isValid) {
                        // Verification passed, write original body
                        DataBuffer buffer = getDelegate().bufferFactory().wrap(responseBodyBytes);
                        return super.writeWith(Mono.just(buffer));
                    } else {
                        // Verification failed, set error response
                        return setErrorResponse(getDelegate(), "Verification failed");
                    }
                });
    }

    private String computeSha256Digest(byte[] data) {
        // Replace with your actual digest computation logic
        return "computed-digest-placeholder";
    }

    private Mono<Void> setErrorResponse(ServerHttpResponse response, String message) {
        response.setStatusCode(HttpStatus.BAD_REQUEST);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        String errorBody = "{\"error\": \"" + message + "\"}";
        DataBuffer buffer = response.bufferFactory().wrap(errorBody.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }
}