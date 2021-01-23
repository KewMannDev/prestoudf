package com.trinoudf.crypto;

import java.util.Base64;

/**
 * ==Description==
 * <p>
 *     Decodes Base64 String.
 * </p>
 * ===Objects===
 * <p>This class contains the following objects when instantiated:</p>
 * <ul>
 *     <li>decoder</li>
 * </ul>
 * ===Methods===
 * <p>This class contains the following methods when instantiated:</p>
 * <ul>
 *     <li>Decoder()</li>
 *     <li>decode(String payload)</li>
 * </ul>
 *
 * @author Wong Kok-Lim
 */
public class Decoder {
    private static final Base64.Decoder decoder = Base64.getDecoder();

    /**
     * Constructor for Decoder class.
     * @author Wong Kok-Lim
     */
    private Decoder() {
    }

    /**
     * Decodes Base64 String.
     * @param payload Base64 String to decode.
     * @return Decoded byte[].
     * @author Wong Kok-Lim
     */
    public static byte[] decode(String payload) {
        return decoder.decode(payload);
    }

}
