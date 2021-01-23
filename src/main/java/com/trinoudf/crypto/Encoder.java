package com.trinoudf.crypto;

import java.nio.ByteBuffer;
import java.util.Base64;

/**
 * ==Description==
 * <p>Encodes String in Base64.</p>
 * ===Objects===
 * <p>This class contains the following objects when instantiated:</p>
 * <ul>
 *     <li>encoder</li>
 * </ul>
 * ===Methods===
 * <p>This class contains the following methods when instantiated:</p>
 * <ul>
 *     <li>Encoder()</li>
 *     <li>encode(byte[] payload)</li>
 *     <li>encode(ByteBuffer payload)</li>
 * </ul>
 *
 * @author Wong Kok-Lim
 */
public class Encoder {
    private static final Base64.Encoder encoder = Base64.getEncoder();

    /**
     * Constructor for Encoder class.
     * @author Wong Kok-Lim
     */
    private Encoder() {
    }

    /**
     * Encodes byte[] in Base64.
     * @param payload Base64 byte[] to encode.
     * @return Encoded Base64 String.
     * @author Wong Kok-Lim
     */
    public static String encode(byte[] payload) {
        return encoder.encodeToString(payload);
    }

    /**
     * Encodes ByteBuffer in Base64.
     * @param payload Base64 ByteBuffer to encode.
     * @return Encoded Base64 ByteBuffer.
     * @author Wong Kok-Lim
     */
    public static ByteBuffer encode(ByteBuffer payload) {
        return encoder.encode(payload);
    }
}
