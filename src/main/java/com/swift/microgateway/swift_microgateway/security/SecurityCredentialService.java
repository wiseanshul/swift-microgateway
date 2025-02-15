package com.swift.microgateway.swift_microgateway.security;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.util.concurrent.CompletableFuture;

@Service
public class SecurityCredentialService {

    private final RestTemplate restTemplate;

    public SecurityCredentialService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }


    public CompletableFuture<SecurityCredentials> fetchSecurityCredentials(String server) {
        CompletableFuture<String> privateKeyFuture = CompletableFuture.supplyAsync(() -> {
            String response = restTemplate.getForObject(server + "/sandbox-selfsigned-dummy-secret/privatekey2", String.class);
            return "-----BEGIN PRIVATE KEY-----\n" + response.trim() + "\n-----END PRIVATE KEY-----";
        });

        CompletableFuture<String> certificateFuture = CompletableFuture.supplyAsync(() ->
                restTemplate.getForObject(server + "/sandbox-selfsigned-dummy-secret/certificate2", String.class)
        );

        return privateKeyFuture.thenCombine(certificateFuture, SecurityCredentials::new);
    }

    public static class SecurityCredentials {
        private final String privateKey;
        private final String certificate;

        public SecurityCredentials(String privateKey, String certificate) {
            this.privateKey = privateKey;
            this.certificate = certificate;
        }

        public String getPrivateKey() { return privateKey; }
        public String getCertificate() { return certificate; }
    }
}
