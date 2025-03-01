package com.swift.microgateway.swift_microgateway.configuration;

import com.swift.microgateway.swift_microgateway.common.JsonCanonicalizer;
import com.swift.microgateway.swift_microgateway.security.JwtUtil;
import com.swift.microgateway.swift_microgateway.security.SecurityCredentialService;
import org.reactivestreams.Publisher;
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
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
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
     String jwt;
    String computeSha256DigestOfResponseBody="";
    @Override
    public int getOrder() {
        return -1; // High priority execution
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String accessToken = exchange.getRequest().getHeaders().getFirst("X-Access-Token");
        String  X_SWIFT_Signature = exchange.getRequest().getHeaders().getFirst("X-SWIFT-Signature");
        logger.info("Access Token: " + accessToken);
        logger.info(" X_SWIFT_Signature : "+X_SWIFT_Signature );
        if(X_SWIFT_Signature!=null) {
          //info : non-repudiation
            return DataBufferUtils.join(exchange.getRequest().getBody())
                    .flatMap(dataBuffer -> {
                        byte[] requestBodyBytes = new byte[dataBuffer.readableByteCount()];
                        dataBuffer.read(requestBodyBytes);
                        DataBufferUtils.release(dataBuffer); // Release buffer
                        logger.info("success 1");
                        ServerHttpRequest decoratedRequest;

                        decoratedRequest = createSwiftJwtSignature(exchange, requestBodyBytes, accessToken);
                        // Decorate the response using a method,
                        ServerHttpResponse decoratedResponse = computeJsonCanonicalizedDigestOfResponse(exchange.getResponse(),exchange);
                        logger.info(" s4 ");
                        return chain.filter(exchange.mutate().request(decoratedRequest).response(decoratedResponse).build());
                    });
        }else{
            logger.info("inside else ");
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

    private ServerHttpRequest createSwiftJwtSignature(ServerWebExchange exchange, byte[] requestBodyBytes, String accessToken) {
        String jwt = getJwt(requestBodyBytes, exchange.getRequest().getURI().toString());
        logger.info("jwt : "+jwt);
        this.jwt=jwt;
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
        return decoratedRequest;
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

        } catch (InterruptedException | ExecutionException e) {
            throw new RuntimeException(e);
        }

    }

    private Mono<Boolean> verifyXSwiftIntegrityHeader(ServerWebExchange exchange) {
        String date = exchange.getResponse().getHeaders().getFirst("Date");
        logger.info("date response header 2 : "+date);
        String xSwiftIntegrity =  exchange.getResponse().getHeaders().getFirst("X-SWIFT-Integrity");
        if(xSwiftIntegrity == null ){
            return Mono.just(false);
        }
        Boolean isJwtValid = jwtUtil.verifyJwtSignatureAndExpiration(xSwiftIntegrity);
        logger.info("isJwtValid : "+isJwtValid);
//        if (b){
//            return setErrorResponse(exchange.getResponse(),"non-reputation failed");
//        }
        logger.info(" ******* : "+computeSha256DigestOfResponseBody);
        logger.info("jwt : "+xSwiftIntegrity);
        String digest = JwtUtil.extractDigestFromJwt(xSwiftIntegrity);
        logger.info("digest : "+digest);
           boolean verificationPassed = isJwtValid && computeSha256DigestOfResponseBody.equals(digest);
       return Mono.just(verificationPassed);
       // return Mono<isJwtValid && computeSha256DigestOfResponseBody.equals(digest)>;
    }


    private ServerHttpResponse computeJsonCanonicalizedDigestOfResponse(ServerHttpResponse response, ServerWebExchange exchange) {
        return new ServerHttpResponseDecorator(response) {
            @Override
            public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                return DataBufferUtils.join(Flux.from(body))
                        .switchIfEmpty(Mono.just(getDelegate().bufferFactory().wrap(new byte[0]))) // Handle empty body
                        .flatMap(dataBuffer -> {
                            byte[] responseBodyBytes = new byte[dataBuffer.readableByteCount()];
                            dataBuffer.read(responseBodyBytes);
                            DataBufferUtils.release(dataBuffer);
                            String responseBody = new String(responseBodyBytes, StandardCharsets.UTF_8);
                            logger.info("Response Body: " + responseBody);

                            try {
                                String canonicalizeJson = JsonCanonicalizer.canonicalizeJson(responseBody);
                                String computeSha256Digest = JsonCanonicalizer.computeSha256Digest(canonicalizeJson);
                                computeSha256DigestOfResponseBody = computeSha256Digest;

                                logger.info("canonicalizeJson : " + canonicalizeJson);
                                logger.info("computeSha256Digest : " + computeSha256Digest);
                                logger.info("Date Header: " + exchange.getResponse().getHeaders().getFirst("Date"));
                                logger.info(" s1 ");

                                return verifyXSwiftIntegrityHeader(exchange)
                                        .flatMap(isValid -> {
                                            if (!isValid) {

                                               /** getting issue in this part
                                                logger.info("s2 - Invalid request detected");
                                                setStatusCode(HttpStatus.BAD_REQUEST); // Use decorator’s method
                                                getHeaders().add("Content-Type", "application/json");
                                                String errorMessage = "{\"error\": \"Invalid request\"}";
                                                DataBuffer buffer = getDelegate().bufferFactory().wrap(errorMessage.getBytes());
                                                return getDelegate().writeWith(Mono.just(buffer)).doOnSuccess(v -> logger.info("s2 -  response written successfully"))
                                                        .doOnError(e -> logger.error("s2 - Error in writing response", e));
                                                **/
                                                setStatusCode(HttpStatus.BAD_REQUEST);
                                                DataBuffer buffer = getDelegate().bufferFactory().wrap(responseBodyBytes);
                                                return getDelegate().writeWith(Mono.just(buffer));
                                            }
                                            DataBuffer buffer = getDelegate().bufferFactory().wrap(responseBodyBytes);
                                            return getDelegate().writeWith(Mono.just(buffer));
                                        });
                            } catch (Exception e) {
                                setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                                getHeaders().add("Content-Type", "application/json");
                                String errorMessage = "{\"error\": \"Server error: " + e.getMessage() + "\"}";
                                DataBuffer buffer = getDelegate().bufferFactory().wrap(errorMessage.getBytes());
                                return getDelegate().writeWith(Mono.just(buffer));
                            }
                        });
            }
        };
    }


    private Mono<Void> setErrorResponse(ServerHttpResponse response, String errorMessage) {
        response.setStatusCode(HttpStatus.BAD_REQUEST);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        String errorResponse = "{\"error\": \"" + errorMessage + "\"}";
        DataBuffer buffer = response.bufferFactory().wrap(errorResponse.getBytes(StandardCharsets.UTF_8));
        logger.info(" s3 ");
        return response.writeWith(Mono.just(buffer))
                .doOnSuccess(v -> logger.info("Error response written: " + errorMessage))
                .then(Mono.empty()); // Ensure completion
    }
}

