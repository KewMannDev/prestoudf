package com.prestoudf.secret;

import com.prestoudf.crypto.AesDecrypt;
import com.prestoudf.crypto.Decoder;
import io.airlift.slice.Slice;
import io.prestosql.spi.function.Description;
import io.prestosql.spi.function.ScalarFunction;
import io.prestosql.spi.function.SqlType;
import io.prestosql.spi.type.StandardTypes;

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
    public static Slice decryptStringAES(@SqlType(StandardTypes.VARCHAR) Slice secureData, @SqlType(StandardTypes.VARCHAR) Slice key, @SqlType(StandardTypes.VARCHAR) Slice iv) {
        AesDecrypt decrypt = null;
        try {
            decrypt = new AesDecrypt(secureData.toStringUtf8(), key.toStringUtf8(), iv.toStringUtf8());
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        assert decrypt != null;
        return utf8Slice(decrypt.getDecryptedStr());
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
    public static Slice decryptBinaryAES(@SqlType(StandardTypes.VARCHAR) Slice secureData, @SqlType(StandardTypes.VARCHAR) Slice key, @SqlType(StandardTypes.VARCHAR) Slice iv) {
        ByteBuffer data = ByteBuffer.wrap(Decoder.decode(secureData.toStringUtf8()));
        AesDecrypt decrypt = new AesDecrypt(data, key.toStringUtf8(), iv.toStringUtf8());
        return wrappedBuffer(decrypt.getDecryptedByteBuffer());
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
    public static Slice decryptIpAES(@SqlType(StandardTypes.VARCHAR) Slice secureData, @SqlType(StandardTypes.VARCHAR) Slice key, @SqlType(StandardTypes.VARCHAR) Slice iv) {
        ByteBuffer data = ByteBuffer.wrap(Decoder.decode(secureData.toStringUtf8()));
        AesDecrypt decrypt = new AesDecrypt(data, key.toStringUtf8(), iv.toStringUtf8());
        return wrappedBuffer(decrypt.getDecryptedByteBuffer()).slice(0, 16);
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
    public static Slice decryptUuidAES(@SqlType(StandardTypes.VARCHAR) Slice secureData, @SqlType(StandardTypes.VARCHAR) Slice key, @SqlType(StandardTypes.VARCHAR) Slice iv) {
        ByteBuffer data = ByteBuffer.wrap(Decoder.decode(secureData.toStringUtf8()));
        AesDecrypt decrypt = new AesDecrypt(data, key.toStringUtf8(), iv.toStringUtf8());
        return wrappedBuffer(decrypt.getDecryptedByteBuffer()).slice(0, 16);
    }
}
