package com.prestoudf.crypto;

import com.prestoudf.global.Config;
import com.prestoudf.key.KeyGenerator;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * ==Description==
 * <p>
 *     Encrypts a given String using AES.
 * </p>
 * ===Objects===
 * <p>This class contains the following objects when instantiated:</p>
 * <ul>
 *     <li>encryptedStr</li>
 *     <li>encryptedByteBuffer</li>
 * </ul>
 *
 * ===Methods===
 * <p>This class contains the following methods when instantiated:</p>
 * <ul>
 *     <li>AesEncrypt(String payload, String key, String initVector)</li>
 *     <li>AesEncrypt(ByteBuffer payload, String key, String initVector)</li>
 *     <li>getEncryptedStr()</li>
 *     <li>getEncryptedByteBuffer()</li>
 * </ul>
 *
 * @author Wong Kok-Lim
 * @example
 */
public class AESEncrypter implements Encrypter {

    public AESEncrypter() {
    }

    /**
     * Encrypts given String with AES CBC.
     * @param payload String to be encrypted.
     * @param key String key to use for encryption.
     * @param initVector Initialize Vector to use for encryption.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @author Wong Kok-Lim
     */
    public String encryptString(String payload, String key, String initVector) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec skeySpec = KeyGenerator.aesKeySpecGenerator(key);

        Cipher cipher = Cipher.getInstance(Config.AES_TRANSFORM);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        byte[] data = cipher.doFinal(payload.getBytes());

        // encode base64
        return Encoder.encode(data).replaceAll("\n", "").replaceAll("\r", "");
    }

    /**
     * Encrypts given ByteBuffer with AES CBC.
     * @param payload ByteBuffer to be encrypted.
     * @param key Key String to use for encryption.
     * @param initVector Initialize Vector to use for encryption
     * @author Wong Kok-Lim
     */
    public ByteBuffer encryptByteBuffer(ByteBuffer payload, String key, String initVector) {
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec skeySpec = KeyGenerator.aesKeySpecGenerator(key);

        if ( payload == null || !payload.hasRemaining() ) {
            return payload;
        }
        else {
            try {
                Cipher cipher = Cipher.getInstance(Config.AES_TRANSFORM);
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
                ByteBuffer encrypted = ByteBuffer.allocate(cipher.getOutputSize(payload.remaining()));
                cipher.doFinal(payload, encrypted);
                encrypted.rewind();

                // encode base64
                return Encoder.encode(encrypted);
            }
            catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
