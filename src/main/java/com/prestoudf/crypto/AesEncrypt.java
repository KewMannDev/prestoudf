package com.prestoudf.crypto;

import com.prestoudf.global.Config;

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Base64.*;

/**
 * ==Description==
 * <p>
 *     Encrypts a given String using AES.
 * </p>
 * ===Objects===
 * <p>This class contains the following objects when instantiated:</p>
 * <ul>
 *     <li>encryptedStr</li>
 * </ul>
 *
 * ===Methods===
 * <p>This class contains the following methods when instantiated:</p>
 * <ul>
 *     <li>AesEncrypt(String payload, SecretKey aesKey)</li>
 *     <li>getEncryptedStr()</li>
 * </ul>
 *
 * @author Wong Kok-Lim
 * @example
 */
public class AesEncrypt {
    private String encryptedStr;
    private ByteBuffer encryptedByteBuffer;

    /**
     * Constructor for AesEncrypt class. Encrypts given String with AES.
     * @param payload String to be encrypted.
     * @param aesKey AES key to use for encryption.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @author Wong Kok-Lim
     */
    public AesEncrypt(String payload, SecretKey aesKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(Config.AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] data = cipher.doFinal(payload.getBytes());

        // encode base64
        Encoder encoder = Base64.getEncoder();
        this.encryptedStr = encoder.encodeToString(data).replaceAll("\n", "").replaceAll("\r", "");
    }

    /**
     * Constructor for AesEncrypt class. Encrypts given ByteBuffer with AES.
     * @param payload ByteBuffer to be encrypted.
     * @param aesKey AES key to use for encryption.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @author Wong Kok-Lim
     */
    public AesEncrypt(ByteBuffer payload, SecretKey aesKey) {
        if ( payload == null || !payload.hasRemaining() ) {
            this.encryptedByteBuffer = payload;
        }
        try {
            Cipher cipher = Cipher.getInstance(Config.AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            ByteBuffer encrypted = ByteBuffer.allocate(cipher.getOutputSize(payload.remaining()));
            cipher.doFinal(payload, encrypted);
            encrypted.rewind();

            // encode base64
            Encoder encoder = Base64.getEncoder();
            this.encryptedByteBuffer = encoder.encode(encrypted);
        }
        catch ( Exception e ) {
            throw new IllegalStateException( e );
        }
    }

    /**
     * Gets the AES encrypted String.
     * @return AES Encrypted String.
     * @author Wong Kok-Lim.
     */
    public String getEncryptedStr() {
        return this.encryptedStr;
    }

    public ByteBuffer getEncryptedByteBuffer() {
        return this.encryptedByteBuffer;
    }
}
