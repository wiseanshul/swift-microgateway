package com.swift.microgateway.swift_microgateway.common;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

public class JsonCanonicalizer {

    private static final ObjectMapper mapper = new ObjectMapper()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    /**
     * Canonicalizes JSON according to RFC 8785
     * @param jsonString Input JSON string
     * @return Canonicalized JSON string
     * @throws Exception If there is an error during parsing
     */
    public static String canonicalizeJson(String jsonString) throws Exception {
        // Parse the JSON string
        JsonNode jsonNode = mapper.readTree(jsonString);

        // Convert to canonicalized JSON
        String canonicalJson = mapper.writeValueAsString(sortJson(jsonNode));
        return canonicalJson;
    }

    /**
     * Sorts JSON object (in lexicographical order)
     * @param node JSON node
     * @return Sorted JSON node
     */
    private static JsonNode sortJson(JsonNode node) {
        if (node.isObject()) {
            ObjectNode objectNode = (ObjectNode) node;
            TreeMap<String, JsonNode> sortedMap = new TreeMap<>();

            Iterator<Map.Entry<String, JsonNode>> fields = objectNode.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                sortedMap.put(field.getKey(), sortJson(field.getValue()));
            }

            ObjectNode sortedNode = mapper.createObjectNode();
            sortedMap.forEach(sortedNode::set);
            return sortedNode;
        } else if (node.isArray()) {
            // For arrays, process each element
            for (int i = 0; i < node.size(); i++) {
                sortJson(node.get(i));
            }
            return node;
        }
        return node; // No changes for primitive values
    }

    /**
     * Computes SHA256 digest of the canonicalized JSON
     * @param canonicalJson Canonicalized JSON string
     * @return Digest in Hex format
     * @throws NoSuchAlgorithmException If SHA256 is not available
     */
    public static String computeSha256Digest(String canonicalJson) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedBytes = digest.digest(canonicalJson.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hashedBytes);
    }

    /**
     * Converts bytes to Hex string
     * @param bytes Input bytes
     * @return Hex string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

}
