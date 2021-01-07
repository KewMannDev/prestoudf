package com.prestoudf.key;

import com.prestoudf.global.Config;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * ==Description==<br/>
 * <p>
 *     Generates java.security.PrivateKey, java.security.PublicKey & javax.crypto.SecretKey (i.e. AES key) objects. <br/>
 *     This class also generates encrypted String of java.security.PrivateKey & java.security.PublicKey in PEM format.
 * </p><br/>
 * ===Objects===<br/>
 * <p>This class contains the following objects when instantiated:</p>
 * <ul>
 *     <li>keyObj</li>
 *     <li>privateKey</li>
 *     <li>publicKey</li>
 *     <li>privateKeyPEMStr</li>
 *     <li>publicKeyPEMStr</li>
 *     <li>aesKey</li>
 *     <li>aesKeySpec</li>
 * </ul>
 * ===Methods===<br/>
 * <p>This class contains the following methods when instantiated:</p>
 * <ul>
 *     <li>KeyGenerator()</li>
 *     <li>keyCreator()</li>
 *     <li>privateKeyPemStrGenerator()</li>
 *     <li>publicKeyPemStrGenerator()</li>
 *     <li>pemStrGenerator(PemObject pemObj)</li>
 *     <li>getPrivateKey()</li>
 *     <li>getPublicKey()</li>
 *     <li>getAesKeySpec()</li>
 *     <li>getAesKey()</li>
 *     <li>getPrivateKeyPEMStr()</li>
 *     <li>setPrivateKeyPEMStr()</li>
 *     <li>getPublicKeyPEMStr()</li>
 *     <li>setPublicKeyPEMStr()</li>
 * </ul>
 *
 * @author Wong Kok-Lim
 */
public class KeyGenerator {
    /**
     * Constructor for com.pretoudf.key.KeyGenerator class
     * @return N/A
     * @author Wong Kok-Lim
     */
    private KeyGenerator() {
    }

    /**
     * Generates SecretKeySpec from a key String.
     * @param key Key String to be used in SecretKeySpec generation.
     * @return SecretKeySpec base on provided key String.
     * @author Wong Kok-Lim
     */
    public static SecretKeySpec aesKeySpecGenerator(String key) {
        return new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), Config.AES_ALGORITHM);
    }
}
