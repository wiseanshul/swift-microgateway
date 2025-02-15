package com.swift.microgateway.swift_microgateway.security;

import com.fasterxml.jackson.databind.JsonNode;
import io.jsonwebtoken.Jwt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

@RestController
public class AuthController {
    @Autowired
    SecurityCredentialService securityCredentialService;
    @Autowired
    JwtUtil jwtUtil;
    @Autowired
    AuthServices authServices;

    @GetMapping("/auth")
    public ResponseEntity<JsonNode> fetchCredentials(@RequestParam String clintId, @RequestParam String clintSecret, @RequestParam String scope) throws ExecutionException, InterruptedException {
        UserLogin userLogin=new UserLogin(clintId,clintSecret,scope);
        return authServices.authentication(userLogin);
    }

    @GetMapping("/refresh-token")
    public ResponseEntity<JsonNode> refreshToken(@RequestParam String clintId, @RequestParam String clintSecret, @RequestParam String refreshToken, @RequestParam String scope) throws Exception {
        return authServices.refreshToken(refreshToken,clintId,clintSecret,scope);
    }

}
