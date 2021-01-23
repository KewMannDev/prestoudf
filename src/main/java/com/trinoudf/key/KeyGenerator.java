package com.trinoudf.key;

import io.airlift.slice.Slices;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * ==Description==<br/>
 * <p>
 *     Generates javax.crypto.SecretKeySpec (i.e. AES key) objects. <br/>
 * </p><br/>
 * ===Objects===<br/>
 * <p>This class does not contain any objects when instantiated.</p>
 *
 * ===Methods===<br/>
 * <p>This class contains the following methods when instantiated:</p>
 * <ul>
 *     <li>KeyGenerator()</li>
 *     <li>aesHmacKeySpecGenerator(String key)</li>
 *     <li>aesKeySpecGenerator(String key)</li>
 * </ul>
 *
 * @author Wong Kok-Lim
 */
public class KeyGenerator {
    private static final String keyAlgorithm = "AES";
    private static final String msgDigestAlgorithm = "SHA-256";
    private static final int iterationCount = 65536;
    private static final int keyStrength = 256;

    /**
     * Constructor for com.pretoudf.key.KeyGenerator class
     * @return N/A
     * @author Wong Kok-Lim
     */
    private KeyGenerator() {
    }

    /**
     * Generates SecretKeySpec from a key String using HMAC.
     * @param key Key String to be used in SecretKeySpec generation.
     * @return SecretKeySpec base on provided key String.
     * @author Wong Kok-Lim
     */
    public static SecretKeySpec aesHmacKeySpecGenerator(String key) {
        SecretKeySpec secret = null;

        byte[] salt = Slices.wrappedBuffer(key.getBytes()).slice(0, 8).getBytes();

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(key.toCharArray(), salt, iterationCount, keyStrength);
            SecretKey tmp = factory.generateSecret(spec);
            secret = new SecretKeySpec(tmp.getEncoded(), keyAlgorithm);
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return secret;
    }

    /**
     * Generates SecretKeySpec from a key String using SHA.
     * @param key Key String to be used in SecretKeySpec generation.
     * @return SecretKeySpec base on provided key String.
     * @author Wong Kok-Lim
     */
    public static SecretKeySpec aesShaKeySpecGenerator(String key) {
        byte[] secretKey = null;

        try {
            MessageDigest md = MessageDigest.getInstance(msgDigestAlgorithm);
            secretKey = md.digest(key.getBytes(StandardCharsets.UTF_8));
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        assert secretKey != null;
        return new SecretKeySpec(secretKey, keyAlgorithm);
    }
}
