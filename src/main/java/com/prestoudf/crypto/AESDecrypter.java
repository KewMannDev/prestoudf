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
 *     Decrypts a given AES encrypted String.
 * </p>
 * ===Objects===
 * <p>This class contains the following objects when instantiated:</p>
 * <ul>
 *     <li>decryptedStr</li>
 *     <li>decryptedByteBuffer</li>
 * </ul>
 *
 * ===Methods===
 * <p>This class contains the following methods when instantiated:</p>
 * <ul>
 *     <li>AesDecrypt(String payload, String key, String initVector)</li>
 *     <li>AesDecrypt(ByteBuffer payload, String key, String initVector)</li>
 *     <li>getDecryptedStr()</li>
 *     <li>getDecryptedByteBuffer()</li>
 * </ul>
 *
 * @author Wong Kok-Lim
 * @example
 */
public class AESDecrypter implements Decrypter {
    public AESDecrypter() {
    }

    /**
     * Decrypts given AES CBC encrypted String.
     * @param payload AES CBC encrypted String to decrypt.
     * @param key AES CBC key to use for decryption.
     * @param initVector Initialize Vector to use for decryption.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @author Wong Kok-Lim
     */
    public String decryptString(String payload, String key, String initVector) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec skeySpec = KeyGenerator.aesKeySpecGenerator(key);

        byte[] data = Decoder.decode(payload);

        Cipher cipher = Cipher.getInstance(Config.AES_TRANSFORM);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        return new String(cipher.doFinal(data));
    }

    /**
     * Decrypts AES CBC encrypted ByteBuffer.
     * @param payload AES encrypted ByteBuffer to decrypt.
     * @param key Key String to use for decryption.
     * @param initVector Initialize Vector to use for decryption.
     * @author Wong Kok-Lim
     */
    public ByteBuffer decryptByteBuffer(ByteBuffer payload, String key, String initVector) {
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));

        SecretKeySpec skeySpec = KeyGenerator.aesKeySpecGenerator(key);

        if (payload == null || !payload.hasRemaining()) {
            return payload;
        } else {
            try {
                Cipher cipher = Cipher.getInstance(Config.AES_TRANSFORM);
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

                ByteBuffer decrypted = ByteBuffer.allocate(cipher.getOutputSize(payload.remaining()));
                cipher.doFinal(payload, decrypted);
                decrypted.rewind();

                return decrypted;
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
