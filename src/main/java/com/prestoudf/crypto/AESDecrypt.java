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
 *     Interface class for decryption methods.
 * </p>
 * ===Objects===
 * <p>This class does not contain any objects when instantiated.</p>
 *
 * ===Methods===
 * <p>This class contains the following methods when instantiated:</p>
 * <ul>
 *     <li>stringAES(String secureData, String key, String iv)</li>
 *     <li>byteBufferAES(String secureData, String key, String iv)</li>
 * </ul>
 *
 * @author Wong Kok-Lim
 */
public class AESDecrypt {
    /**
     * AES CBC decryption of AES CBC encrypted String.
     * @param secureData AES CBC encrypted String to be decrypted.
     * @param key Key String to use for decryption.
     * @param iv Initializer Vector to use for decryption.
     * @return AES CBC decrypted String.
     * @author Wong Kok-Lim
     */
    protected static Slice stringAES(String secureData, String key, String iv) {
        String decrypt = null;
        try {
            decrypt = new AESDecrypter().decryptString(secureData, key, iv);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        assert decrypt != null;
        return utf8Slice(decrypt);
    }

    /**
     * AES decryption of AES CBC encrypted ByteBuffer.
     * @param secureData AES CBC encrypted String to be decrypted.
     * @param key Key String to use for decryption.
     * @param iv Initializer Vector to use for decryption.
     * @return Decrypted ByteBuffer.
     * @author Wong Kok-Lim
     */
    protected static Slice byteBufferAES(String secureData, String key, String iv) {
        ByteBuffer data = ByteBuffer.wrap(Decoder.decode(secureData));
        ByteBuffer decrypt = new AESDecrypter().decryptByteBuffer(data, key, iv);
        return wrappedBuffer(decrypt);
    }
}
