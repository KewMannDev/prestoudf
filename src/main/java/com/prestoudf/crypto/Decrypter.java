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
 *   Interface class for Decrypter classes.
 * </p>
 * ===Objects===
 * <p>This class does not contain any objects when instantiated.</p>
 * ===Methods===
 * <p>This class contains the following methods when instantiated:</p>
 * <ul>
 *     <li>decryptString(String payload, String key, String initVector)</li>
 *     <li>decryptByteBuffer(ByteBuffer payload, String key, String initVector)</li>
 * </ul>
 *
 * @author Wong Kok-Lim
 * @example
 */
interface Decrypter {
    String decryptString(String payload, String key, String initVector) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException;
    ByteBuffer decryptByteBuffer(ByteBuffer payload, String key, String initVector);
}
