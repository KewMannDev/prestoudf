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
 * </ul>
 *
 * ===Methods===
 * <p>This class contains the following methods when instantiated:</p>
 * <ul>
 *     <li>AesDecrypt(String payload, SecretKey aesKey)</li>
 *     <li>getDecryptedStr()</li>
 * </ul>
 *
 * @author Wong Kok-Lim
 * @example
 */
public class AesDecrypt {
    private String decryptedStr;
    private ByteBuffer decryptedByteBuffer;

    /**
     * Constructor for AesDecrypt class. Decrypts given AES encrypted String.
     * @param payload AES encrypted String to decrypt.
     * @param aesKey AES key to use for decryption.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @author Wong Kok-Lim
     */
    public AesDecrypt(String payload, SecretKey aesKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] data = Decoder.decode(payload);

        Cipher cipher = Cipher.getInstance(Config.AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        this.decryptedStr = new String(cipher.doFinal(data));
    }

    /**
     * Constructor for AesDecrypt class. Decrypts given AES CBC encrypted String.
     * @param payload AES encrypted String to decrypt.
     * @param key AES key to use for decryption.
     * @param initVector Initialize Vector to use for decryption.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @author Wong Kok-Lim
     */
    public AesDecrypt(String payload, String key, String initVector) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec skeySpec = KeyGenerator.aesKeySpecGenerator(key);

        byte[] data = Decoder.decode(payload);

        Cipher cipher = Cipher.getInstance(Config.AES_TRANSFORM);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        this.decryptedStr = new String(cipher.doFinal(data));
    }

    /**
     * Constructor for AesDecrypt class. Decrypts given ByteBuffer.
     * @param payload AES encrypted ByteBuffer to decrypt.
     * @param aesKey AES key to use for decryption.
     * @author Wong Kok-Lim
     */
    public AesDecrypt(ByteBuffer payload, SecretKey aesKey) {
        if ( payload == null || !payload.hasRemaining() ) {
            this.decryptedByteBuffer = payload;
        }
        else {
            try {
                Cipher cipher = Cipher.getInstance(Config.AES_ALGORITHM);
                cipher.init(Cipher.DECRYPT_MODE, aesKey);

                ByteBuffer decrypted = ByteBuffer.allocate(cipher.getOutputSize(payload.remaining()));
                cipher.doFinal(payload, decrypted);
                decrypted.rewind();

                this.decryptedByteBuffer = decrypted;
            }
            catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    /**
     * Constructor for AesDecrypt class. Decrypts given ByteBuffer.
     * @param payload AES encrypted ByteBuffer to decrypt.
     * @param key Key String to use for decryption.
     * @param initVector Initialize Vector to use for decryption.
     * @author Wong Kok-Lim
     */
    public AesDecrypt(ByteBuffer payload, String key, String initVector) {
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec skeySpec = KeyGenerator.aesKeySpecGenerator(key);

        if ( payload == null || !payload.hasRemaining() ) {
            this.decryptedByteBuffer = payload;
        }
        else {
            try {
                Cipher cipher = Cipher.getInstance(Config.AES_TRANSFORM);
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

                ByteBuffer decrypted = ByteBuffer.allocate(cipher.getOutputSize(payload.remaining()));
                cipher.doFinal(payload, decrypted);
                decrypted.rewind();

                this.decryptedByteBuffer = decrypted;
            }
            catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    /**
     * Gets the decrypted String.
     * @return Decrypted String.
     * @author Wong Kok-Lim
     */
    public String getDecryptedStr() {
        return this.decryptedStr;
    }

    /**
     * Gets the AES decrypted ByteBuffer.
     * @return AES Decrypted ByteBuffer.
     * @author Wong Kok-Lim.
     */
    public ByteBuffer getDecryptedByteBuffer() {
        return this.decryptedByteBuffer;
    }
}
