package com.prestoudf.crypto;

import com.prestoudf.global.Config;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Base64.Decoder;

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
        Decoder decoder = Base64.getDecoder();
        byte[] data = decoder.decode(payload);

        Cipher cipher = Cipher.getInstance(Config.AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        this.decryptedStr = new String(cipher.doFinal(data));
    }

    /**
     * Gets the decrypted String.
     * @return Decrypted String.
     * @author Wong Kok-Lim
     */
    public String getDecryptedStr() {
        return this.decryptedStr;
    }
}
