package com.prestoudf.global;

/**
 * ==Description==<br/>
 * <p>
 *     Configuration class which contains all configuration values of custom class.
 * </p>
 * ===Objects=== <br/>
 * <p>This class contains the following objects when instantiated:</p>
 * <ul>
 *     <li>AES_KEY_SIZE</li>
 *     <li>PASSPHRASE</li>
 *     <li>AES_ALGORITHM</li>
 *     <li>RSA_ALGORITHM</li>
 *     <li>BC_PROVIDER</li>
 *     <li>ISO_8859_1</li>
 *     <li>PRIVATEKEY_PATH</li>
 *     <li>PUBLICKEY_PATH</li>
 *     <li>AESKEY_PATH</li>
 * </ul>
 * ===Methods===
 * <p>This class does not contains any methods when instantiated.</p>
 *
 * @author Wong Kok-Lim
 * @example
 */
public class Config {
    final static public String AES_ALGORITHM = "AES";
    final static public String AES_TRANSFORM = "AES/CBC/PKCS5PADDING";
}
