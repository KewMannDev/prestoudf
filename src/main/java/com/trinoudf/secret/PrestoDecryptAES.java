package com.trinoudf.secret;

import com.trinoudf.crypto.AESDecrypt;
import com.trinoudf.global.Methods;
import io.airlift.slice.Slice;
import io.trino.spi.function.Description;
import io.trino.spi.function.ScalarFunction;
import io.trino.spi.function.SqlType;
import io.trino.spi.type.StandardTypes;

/**
 * ==Description==
 * <p>
 *     AES decryption methods for PrestoSQL
 * </p>
 * ===Objects===
 * <p>This class does not contains any objects when instantiated.</p>
 *
 * ===Methods===
 * <p>This class contains the following methods when instantiated:</p>
 * <ul>
 *     <li>PrestoDecryptAES()</li>
 *     <li>decryptStringAES(@SqlType(StandardTypes.VARCHAR) Slice secureData, @SqlType(StandardTypes.VARCHAR) Slice key, @SqlType(StandardTypes.VARCHAR) Slice iv)</li>
 *     <li>decryptBinaryAES(@SqlType(StandardTypes.VARCHAR) Slice secureData, @SqlType(StandardTypes.VARCHAR) Slice key, @SqlType(StandardTypes.VARCHAR) Slice iv)</li>
 * </ul>
 *
 * @author koklim
 * @example
 */
public final class PrestoDecryptAES {
    private static final AESDecrypt aesDecrypt = new AESDecrypt(Methods.CBC);

    private PrestoDecryptAES() {
    }

    /**
     * PrestoSQL user defined function for AES decryption of AES encrypted String.
     * @param secureData AES encrypted String to be decrypted.
     * @param key Key String to use for decryption.
     * @param iv Initializer Vector to use for decryption.
     * @return AES decrypted String.
     * @author Wong Kok-Lim
     */
    @Description("Decrypts a string using AES")
    @ScalarFunction("decrypt_aes")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice decryptStringAes(@SqlType(StandardTypes.VARCHAR) Slice secureData, @SqlType(StandardTypes.VARCHAR) Slice key, @SqlType(StandardTypes.VARCHAR) Slice iv) {
        return aesDecrypt.stringAES(secureData.toStringUtf8(), key.toStringUtf8(), iv.toStringUtf8());
    }

    /**
     * PrestoSQL user defined function for AES decryption of AES encrypted Binary data type.
     * @param secureData AES encrypted String to be decrypted.
     * @param key Key String to use for decryption.
     * @param iv Initializer Vector to use for decryption.
     * @return Decrypted binary value.
     * @author Wong Kok-Lim
     */
    @Description("Decrypts a binary using AES")
    @ScalarFunction("decrypt_aes_binary")
    @SqlType(StandardTypes.VARBINARY)
    public static Slice decryptBinaryAes(@SqlType(StandardTypes.VARCHAR) Slice secureData, @SqlType(StandardTypes.VARCHAR) Slice key, @SqlType(StandardTypes.VARCHAR) Slice iv) {
        return aesDecrypt.byteBufferAES(secureData.toStringUtf8(), key.toStringUtf8(), iv.toStringUtf8());
    }

    /**
     * PrestoSQL user defined function for AES CBC decryption of AES CBC encrypted Binary data type.
     * @param secureData AES CBC encrypted String to be decrypted.
     * @param key Key String to use for decryption.
     * @param iv Initializer Vector to use for decryption.
     * @return Decrypted IPADDRESS value.
     * @author Wong Kok-Lim
     */
    @Description("Decrypts a IP address using AES")
    @ScalarFunction("decrypt_aes_ip")
    @SqlType(StandardTypes.IPADDRESS)
    public static Slice decryptIpAes(@SqlType(StandardTypes.VARCHAR) Slice secureData, @SqlType(StandardTypes.VARCHAR) Slice key, @SqlType(StandardTypes.VARCHAR) Slice iv) {
        Slice decrypted = aesDecrypt.byteBufferAES(secureData.toStringUtf8(), key.toStringUtf8(), iv.toStringUtf8());
        return decrypted.slice(0, 16);
    }

    /**
     * PrestoSQL user defined function for AES CBC decryption of AES CBC encrypted UUID data type.
     * @param secureData AES CBC encrypted String to be decrypted.
     * @param key Key String to use for decryption.
     * @param iv Initializer Vector to use for decryption.
     * @return Decrypted UUID value.
     * @author Wong Kok-Lim
     */
    @Description("Decrypts a UUID using AES")
    @ScalarFunction("decrypt_aes_uuid")
    @SqlType(StandardTypes.UUID)
    public static Slice decryptUuidAes(@SqlType(StandardTypes.VARCHAR) Slice secureData, @SqlType(StandardTypes.VARCHAR) Slice key, @SqlType(StandardTypes.VARCHAR) Slice iv) {
        Slice decrypted = aesDecrypt.byteBufferAES(secureData.toStringUtf8(), key.toStringUtf8(), iv.toStringUtf8());
        return decrypted.slice(0, 16);
    }
}
