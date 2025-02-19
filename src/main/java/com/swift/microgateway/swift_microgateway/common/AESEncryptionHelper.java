package com.swift.microgateway.swift_microgateway.common;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESEncryptionHelper {

    private static final String ENC_ALGORITHM = "AES";

    // Hardcoded secret key (Use a secure way to store this in production)
    private static  String FIXED_KEY = ""; // 32 characters for AES-128



    public static String decrypt(String encryptedData,String key) {
        try {
            final SecretKey SECRET_KEY = new SecretKeySpec(key.getBytes(), ENC_ALGORITHM);
            Cipher cipher = Cipher.getInstance(ENC_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, SECRET_KEY);
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting data", e);
        }
    }

}
