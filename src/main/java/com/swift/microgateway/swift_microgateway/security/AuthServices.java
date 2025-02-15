package com.swift.microgateway.swift_microgateway.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.swift.microgateway.swift_microgateway.configuration.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;

@Service
public class AuthServices {

    private final Logger logger = LoggerFactory.getLogger(AuthServices.class);

    String Server = Constants.PROTOCOL + Constants.SERVER;

    @Autowired
    JwtUtil jwtUtil;
    @Autowired
    SecurityCredentialService securityCredentialService;

    public ResponseEntity<JsonNode> authentication(UserLogin userLogin) {
        try {

            String consumerKey = userLogin.getClintId();
            CompletableFuture<SecurityCredentialService.SecurityCredentials> securityCredentialsCompletableFuture = securityCredentialService.fetchSecurityCredentials(Server);
            String key = securityCredentialsCompletableFuture.get().getPrivateKey();
            String certificate = securityCredentialsCompletableFuture.get().getCertificate();
            String jwt = jwtUtil.generateJwtToken(consumerKey, key, certificate);

            if (JwtUtil.validateJWT(jwt,consumerKey)){
              return callTokenApi(jwt, consumerKey, userLogin.getClintSecrets(), userLogin.getScope());
            }
            else {
                throw new IllegalArgumentException("Invalid JWT token");
            }

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }


    public static ResponseEntity<JsonNode> callTokenApi(String jwtToken, String username, String password,String scop) throws Exception {

        // API URL
        String url = Constants.PROTOCOL+Constants.SERVER+Constants.GTW_OAUTH_SERVICE;

        // Create an ObjectMapper for converting JSON
        ObjectMapper objectMapper = new ObjectMapper();

        // Prepare Basic Authentication header
        String auth = username + ":" + password;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
        String authHeader = "Basic " + encodedAuth;

        // Prepare request body parameters (URL-encoded)
        String grantType = URLEncoder.encode("urn:ietf:params:oauth:grant-type:jwt-bearer", StandardCharsets.UTF_8);
        String assertion = URLEncoder.encode(jwtToken, StandardCharsets.UTF_8);
        String scope = URLEncoder.encode(scop, StandardCharsets.UTF_8);

        String requestBody = "grant_type=" + grantType + "&assertion=" + assertion + "&scope=" + scope;

        // Create HttpClient and build the POST request
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", authHeader)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        // Send the request and receive the response
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        // Parse the response string into a JsonNode (Jackson's JSON tree model)
        return ResponseEntity.status(response.statusCode()).body( objectMapper.readTree(response.body()));

    }

    public ResponseEntity<JsonNode> refreshToken(String refreshToken, String username, String password, String scop) throws Exception {

        // API URL
        String url = Constants.PROTOCOL+Constants.SERVER+Constants.GTW_OAUTH_SERVICE;

        // Create an ObjectMapper for converting JSON
        ObjectMapper objectMapper = new ObjectMapper();

        // Prepare Basic Authentication header
        String auth = username + ":" + password;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
        String authHeader = "Basic " + encodedAuth;

        // Prepare request body parameters (URL-encoded)
        String grantType = URLEncoder.encode("refresh_token", StandardCharsets.UTF_8);
        String refresh_token = URLEncoder.encode(refreshToken, StandardCharsets.UTF_8);
        String scope = URLEncoder.encode(scop, StandardCharsets.UTF_8);

        String requestBody = "grant_type=" + grantType + "&refresh_token=" + refresh_token + "&scope=" + scope;

        // Create HttpClient and build the POST request
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", authHeader)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        System.out.println("p : "+requestBody );
        // Send the request and receive the response
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        // Parse the response string into a JsonNode (Jackson's JSON tree model)
        return ResponseEntity.status(response.statusCode()).body( objectMapper.readTree(response.body()));

    }
}





