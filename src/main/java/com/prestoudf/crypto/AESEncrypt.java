package com.prestoudf.crypto;

import io.airlift.slice.Slice;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static io.airlift.slice.Slices.utf8Slice;
import static io.airlift.slice.Slices.wrappedBuffer;

/**
 * ==Description==
 * <p>
 *     Interface class for encryption methods.
 * </p>
 * ===Objects===
 * <p>This class does not contain any objects when instantiated.</p>
 *
 * ===Methods===
 * <p>This class contains the following methods when instantiated:</p>
 * <ul>
 *     <li>stringAES(String privateData, String key, String iv)</li>
 *     <li>byteBufferAES(ByteBuffer privateData, String key, String iv)</li>
 * </ul>
 *
 * @author Wong Kok-Lim
 */
public class AESEncrypt {
    /**
     * AES CBC encryption of Strings.
     * @param privateData String to be encrypted with AES.
     * @param key Key String to use for encryption.
     * @param iv Initializer Vector to use for encryption
     * @return AES Encrypted String.
     * @author Wong Kok-Lim
     */
    protected static Slice stringAES(String privateData, String key, String iv) {
        String encrypt = null;
        try {
            encrypt = new AESEncrypter().encryptString(privateData, key, iv);
        }
        catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        assert encrypt != null;
        return utf8Slice(encrypt);
    }

    /**
     * AES CBC encryption of ByteBuffer.
     * @param privateData ByteBuffer to be encrypted with AES CBC.
     * @param key Key String to use for encryption.
     * @param iv Initializer Vector to use for encryption.
     * @return AES encrypted String.
     * @author Wong Kok-Lim
     */
    protected static Slice byteBufferAES(ByteBuffer privateData, String key, String iv) {
        ByteBuffer encrypt = new AESEncrypter().encryptByteBuffer(privateData, key, iv);
        return wrappedBuffer(encrypt);
    }
}
