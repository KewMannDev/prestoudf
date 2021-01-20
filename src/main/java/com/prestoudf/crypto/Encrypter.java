package com.prestoudf.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * ==Description==
 * <p>
 *     Interface class for Encrypter classes.
 * </p>
 * ===Objects===
 * <p>This class does not contain any objects when instantiated.</p>
 * ===Methods===
 * <p>This class contains the following methods when instantiated:</p>
 * <ul>
 *     <li>encryptString(String payload, String key, String initVector)</li>
 *     <li>encryptByteBuffer(ByteBuffer payload, String key, String initVector)</li>
 * </ul>
 *
 * @author koklim
 * @example
 */
public interface Encrypter {
    String encryptString(String payload, String key, String initVector) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException;
    ByteBuffer encryptByteBuffer(ByteBuffer payload, String key, String initVector);
}
