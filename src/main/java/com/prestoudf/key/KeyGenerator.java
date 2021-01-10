package com.prestoudf.key;

import com.prestoudf.global.Config;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * ==Description==<br/>
 * <p>
 *     Generates javax.crypto.SecretKeySpec (i.e. AES key) objects. <br/>
 * </p><br/>
 * ===Objects===<br/>
 * <p>This class does not contain any objects when instantiated.</p>
 *
 * ===Methods===<br/>
 * <p>This class contains the following methods when instantiated:</p>
 * <ul>
 *     <li>KeyGenerator()</li>
 *     <li>aesKeySpecGenerator(String key)</li>
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
