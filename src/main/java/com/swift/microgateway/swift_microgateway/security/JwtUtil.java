package com.swift.microgateway.swift_microgateway.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.swift.microgateway.swift_microgateway.common.AESEncryptionHelper;
import com.swift.microgateway.swift_microgateway.common.PropertiesService;
import com.swift.microgateway.swift_microgateway.configuration.Constants;
import io.jsonwebtoken.*;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.StringReader;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

@Service
public class JwtUtil {

    @Autowired
    PropertiesService propertiesService;

    public  String generateJwtToken(String consumerKey,String privateKey,String certificate) {
        try {
            String audience = Constants.AUDIENCE;

            String subject = "CN=demo-swift-sandbox-consumer, O=Demo, L=London, S=London, C=GB";
            long expirationTime = 900 * 1000L; // 15 minutes in milliseconds
            long currentTime = System.currentTimeMillis();

            // Convert PEM Private Key to Java PrivateKey Object
            PrivateKey pk = getPrivateKeyFromPem(privateKey);

            // Prepare JWT Claims
            return Jwts.builder()
                    .issuer(consumerKey)  // "iss"
                    .setAudience(audience)   // "aud"
                    .subject(subject)     // "sub"
                    .id(UUID.randomUUID().toString())  // "jti"
                    .issuedAt(new Date(currentTime - 1000))  // "iat" (-1s for clock skew)
                    .expiration(new Date(currentTime + expirationTime)) // "exp"
                    .id(generateSecureJTI())
                    .header().add("typ", "JWT").add("alg", "RS256").add("x5c", new String[]{certificate.replaceAll("\\s+", "")}).and()
                    .signWith(SignatureAlgorithm.RS256, pk)  // Sign JWT
                    .compact();


        } catch (Exception e) {
            throw new RuntimeException("Error generating JWT", e);
        }
    }

    private static String generateSecureJTI() {
        String charset = "abcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder jti = new StringBuilder();
        Random random = new Random();
        for (int i = 0; i < 12; i++) {
            jti.append(charset.charAt(random.nextInt(charset.length())));
        }
        return jti.toString();
    }

    public static PrivateKey getPrivateKeyFromPem(String pem) throws Exception {
        // Remove PEM headers and decode Base64
        PemReader pemReader = new PemReader(new StringReader(pem));
        PemObject pemObject = pemReader.readPemObject();
        pemReader.close();

        byte[] keyBytes = pemObject.getContent();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    public static boolean validateJWT(String jwt,String consumerKey) {
        try {
            // ✅ Split JWT (Header.Payload.Signature)
            String[] parts = jwt.split("\\.");
            if (parts.length != 3) {
                throw new MalformedJwtException("Invalid JWT format");
            }

            // ✅ Decode Payload (Middle Part)
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));

            // ✅ Convert JSON to Claims Map
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> claimsMap = objectMapper.readValue(payloadJson, Map.class);

            // ✅ Extract Claims
            String issuer = (String) claimsMap.get("iss");
            String audience = (String) claimsMap.get("aud");
            Date expiration = new Date((Integer) claimsMap.get("exp") * 1000L); // Convert to milliseconds

            // ✅ Validate Expiration
            if (expiration.before(new Date())) {
                System.out.println("❌ JWT is expired!");
                return false;
            }

            // ✅ Validate Issuer & Audience
            if (!consumerKey.equals(issuer)) {
                System.out.println("❌ JWT Issuer mismatch!");
                return false;
            }

            if (!"sandbox.swift.com/oauth2/v1/token".equals(audience)) {
                System.out.println("❌ JWT Audience mismatch!");
                return false;
            }

            System.out.println("✅ JWT is valid! Claims: " + claimsMap);
            return true;
        } catch (MalformedJwtException e) {
            System.out.println("❌ Invalid JWT format: " + e.getMessage());
        } catch (JwtException e) {
            System.out.println("❌ JWT processing error: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("❌ Unexpected error: " + e.getMessage());
        }
        return false;
    }

    public String getJwtForNonRepudiation(String certificate,String privateKey, String audience,String digest)
    {
        try {


            String subject = "CN=demo-swift-sandbox-consumer, O=Demo, L=London, S=London, C=GB";
            long expirationTime = 900 * 1000L; // 15 minutes in milliseconds
            long currentTime = System.currentTimeMillis();

            // Convert PEM Private Key to Java PrivateKey Object
            PrivateKey pk = getPrivateKeyFromPem(privateKey);

            String consumerSecret = AESEncryptionHelper.decrypt(propertiesService.getPropertyValue("external.clint-secret"),propertiesService.getPropertyValue("external.key"));


            // Prepare JWT Claims
            return Jwts.builder()
                    .issuer(consumerSecret)  // "iss"
                    .setAudience(audience)   // "aud"
                    .subject(subject)     // "sub"
                    .id(UUID.randomUUID().toString())  // "jti"
                    .issuedAt(new Date(currentTime - 1000))  // "iat" (-1s for clock skew)
                    .claim("digest",digest)
                    .expiration(new Date(currentTime + expirationTime)) // "exp"
                    .id(generateSecureJTI())
                    .header().add("typ", "JWT").add("alg", "RS256").add("x5c", new String[]{certificate.replaceAll("\\s+", "")}).and()
                    .signWith(SignatureAlgorithm.RS256, pk)  // Sign JWT
                    .compact();


        } catch (Exception e) {
            throw new RuntimeException("Error generating JWT", e);
        }
    }
}
