package com.prestoudf.test;

import com.prestoudf.crypto.AesDecrypt;
import com.prestoudf.crypto.AesEncrypt;
import com.prestoudf.crypto.Decoder;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static io.airlift.slice.Slices.wrappedBuffer;

import static org.junit.Assert.assertEquals;

/**
 * ==Description==
 * <p>
 *     Unit Test for AES CBC encryption and decryption methods.
 * </p>
 * <br/>
 * ===Objects===
 * <p>This class does not contain any objects when instantiated</p>
 * <br/>
 * ===Methods===
 * <p>This class contains the following methods when instantiated:</p>
 * <ul>
 *     <li>aesCBCEncryptDecryptString()</li>
 *     <li>aesCBCEncryptDecryptByteBuffer()</li>
 * </ul>
 *
 * @author Wong Kok-Lim
 */
public class UnitTest {
    /**
     * Unit test for AES CBC encryption and decryption of String.
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @author Wong Kok-Lim
     */
    @Test
    public void aesCBCEncryptDecryptString() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String expected = "hello2";

        AesEncrypt encrypt = new AesEncrypt(expected, "aesEncryptionKey", "encryptionIntVec");

        AesDecrypt decrypt = new AesDecrypt(encrypt.getEncryptedStr(), "aesEncryptionKey", "encryptionIntVec");
        String decryptStr = decrypt.getDecryptedStr();

        assertEquals(expected, decryptStr);
    }

    /**
     * Unit test for AES CBC encryption and decryption of ByteBuffer.
     * @author Wong Kok-Lim
     */
    @Test
    public void aesCBCEncryptDecryptByteBuffer() {
        String expected = "hello2";

        AesEncrypt encrypt = new AesEncrypt(ByteBuffer.wrap(expected.getBytes()), "aesEncryptionKey", "encryptionIntVec");
        String encryptedStr = wrappedBuffer(encrypt.getEncryptedByteBuffer()).toStringUtf8();

        AesDecrypt decrypt = new AesDecrypt(ByteBuffer.wrap(Decoder.decode(encryptedStr)), "aesEncryptionKey", "encryptionIntVec");
        String decryptStr = wrappedBuffer(decrypt.getDecryptedByteBuffer()).toStringAscii().trim();

        assertEquals(expected, decryptStr);
    }
}
