package com.prestoudf.secret;

import com.prestoudf.crypto.AESEncrypt;
import io.airlift.slice.Slice;
import io.prestosql.spi.function.*;
import io.prestosql.spi.type.StandardTypes;

import java.nio.ByteBuffer;

/**
 * ==Description==
 * <p>
 *     AES Encryption methods for PrestoSQL.
 * </p>
 * ===Objects===
 * <p>This class does not contains any objects when instantiated.</p>
 *
 * ===Methods===
 * <p>This class contains the following methods when instantiated.</p>
 * <ul>
 *     <li>PrestoEncryptAES()</li>
 *     <li>encryptDoubleAES(@SqlNullable @SqlType("T") Double privateData, @SqlNullable @SqlType("U") Slice key, @SqlNullable @SqlType("V") Slice iv)</li>
 *     <li>encryptLongAES(@SqlNullable @SqlType("T") Long privateData, @SqlNullable @SqlType("U") Slice key, @SqlNullable @SqlType("V") Slice iv)</li>
 *     <li>encryptBoolAES(@SqlNullable @SqlType("T") Boolean privateData, @SqlNullable @SqlType("U") Slice key, @SqlNullable @SqlType("V") Slice iv)</li>
 *     <li>encryptBinaryAES(@SqlNullable @SqlType("T") Slice privateData, @SqlNullable @SqlType("U") Slice key, @SqlNullable @SqlType("V") Slice iv)</li>
 * </ul>
 *
 * @author koklim
 */

@ScalarFunction("encrypt_aes")
@Description("Encrypts a string using cipher")
public final class PrestoEncryptAES extends AESEncrypt {
    private PrestoEncryptAES() {
    }
    /**
     * PrestoSQL user defined function for AES encryption of Strings.
     * @param privateData Double to be encrypted with AES.
     * @param key Key String to use for encryption.
     * @param iv Initializer Vector to use for encryption
     * @return AES Encrypted String.
     * @author Wong Kok-Lim
     */
    @TypeParameter("T")
    @TypeParameter("U")
    @TypeParameter("V")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice encryptDoubleAES(@SqlNullable @SqlType("T") Double privateData, @SqlNullable @SqlType("U") Slice key, @SqlNullable @SqlType("V") Slice iv) {
        return stringAES(privateData.toString(), key.toStringUtf8(), iv.toStringUtf8());
    }

    /**
     * PrestoSQL user defined function for AES encryption of Strings.
     * @param privateData Real, Integer, Decimal, TinyInt, SmallInt, BigInt, Date, Timestamp to be encrypted with AES.
     * @param key Key String to use for encryption.
     * @param iv Initializer Vector to use for encryption
     * @return AES Encrypted String.
     * @author Wong Kok-Lim
     */
    @TypeParameter("T")
    @TypeParameter("U")
    @TypeParameter("V")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice encryptLongAES(@SqlNullable @SqlType("T") Long privateData, @SqlNullable @SqlType("U") Slice key, @SqlNullable @SqlType("V") Slice iv) {
        return stringAES(privateData.toString(), key.toStringUtf8(), iv.toStringUtf8());
    }

    /**
     * PrestoSQL user defined function for AES encryption of Strings.
     * @param privateData Boolean to be encrypted with AES.
     * @param key Key String to use for encryption.
     * @param iv Initializer Vector to use for encryption
     * @return AES Encrypted String.
     * @author Wong Kok-Lim
     */
    @TypeParameter("T")
    @TypeParameter("U")
    @TypeParameter("V")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice encryptBoolAES(@SqlNullable @SqlType("T") Boolean privateData, @SqlNullable @SqlType("U") Slice key, @SqlNullable @SqlType("V") Slice iv) {
        return stringAES(privateData.toString(), key.toStringUtf8(), iv.toStringUtf8());
    }

    /**
     * PrestoSQL user defined function for AES encryption of Binary Data.
     * @param privateData VARCHAR, IPADDRESS, UUID, JSON, CHAR, VARBINARY to be encrypted with AES.
     * @param key Key String to use for encryption.
     * @param iv Initializer Vector to use for encryption.
     * @return AES encrypted String.
     * @author Wong Kok-Lim
     */
    @TypeParameter("T")
    @TypeParameter("U")
    @TypeParameter("V")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice encryptBinaryAES(@SqlNullable @SqlType("T") Slice privateData, @SqlNullable @SqlType("U") Slice key, @SqlNullable @SqlType("V") Slice iv) {
        return byteBufferAES(ByteBuffer.wrap(privateData.getBytes()), key.toStringUtf8(), iv.toStringUtf8());
    }
}
