package com.swift.microgateway.swift_microgateway.security;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
public class AuthController {

    @Autowired
    AuthServices authServices;

    @GetMapping("/auth")
    public ResponseEntity<JsonNode> fetchCredentials(@RequestParam String clientId , @RequestParam String scope){
        return authServices.authentication(clientId,scope);
    }

    @GetMapping("/refresh-token")
    public ResponseEntity<JsonNode> refreshToken(@RequestParam String clientId, @RequestParam String refreshToken, @RequestParam String scope) throws Exception {
        return authServices.refreshToken(refreshToken,clientId,scope);
    }

}
