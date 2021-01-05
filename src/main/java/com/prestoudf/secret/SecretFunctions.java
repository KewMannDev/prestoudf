package com.prestoudf.secret;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.regions.DefaultAwsRegionProviderChain;
import com.prestoudf.crypto.AesDecrypt;
import com.prestoudf.crypto.AesEncrypt;
import com.prestoudf.global.Config;
import com.prestoudf.key.KeyGenerator;
import com.prestoudf.key.KeyReader;
import com.prestoudf.key.KeyWriter;
import io.prestosql.spi.connector.ConnectorSession;
import io.prestosql.spi.function.Description;
import io.prestosql.spi.function.ScalarFunction;
import io.prestosql.spi.function.SqlType;
import io.prestosql.spi.security.AccessDeniedException;
import io.prestosql.spi.type.StandardTypes;
import io.airlift.slice.Slice;
import org.jasypt.util.text.BasicTextEncryptor;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import static io.airlift.slice.Slices.utf8Slice;
import static io.airlift.slice.Slices.wrappedBuffer;

public class SecretFunctions {

    private static final String secret = "cipher";

    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static SecretKey aesKey;

    private SecretFunctions(){
        KeyWriter writer = new KeyWriter();
        KeyReader reader = new KeyReader();
        File privateKeyFileChecker = new File(Config.PRIVATEKEY_PATH);
        File publicKeyFileChecker = new File(Config.PUBLICKEY_PATH);
        File aesKeyFileChecker = new File(Config.AESKEY_PATH);

        if(privateKeyFileChecker.exists() && publicKeyFileChecker.exists() && aesKeyFileChecker.exists()) {
            try {
                privateKey = reader.getPrivateKey();
                publicKey = reader.getPublicKey();
                aesKey = reader.getAesKey(privateKey);
            }
            catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException e) {
                e.printStackTrace();
            }
        }
        else {
            KeyGenerator keygen = KeyGenerator.keyCreator();
            keygen.setPrivateKeyPEMStr();
            keygen.setPublicKeyPEMStr();
            writer.savePrivateKeyPem(keygen.getPrivateKeyPEMStr());
            writer.savePubliceKeyPem(keygen.getPublicKeyPEMStr());

            try {
                privateKey = reader.getPrivateKey();
                publicKey = reader.getPublicKey();
                writer.saveAESKey(keygen.getAesKey(), publicKey);
                aesKey = reader.getAesKey(privateKey);
            }
            catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException e) {
                e.printStackTrace();
            }
        }
    }

    public static void setKeys() {
        new SecretFunctions();
    }

    @Description("Encrypts a string using cipher")
    @ScalarFunction("encrypt")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice encryptString(@SqlType(StandardTypes.VARCHAR) Slice privateData) {
        BasicTextEncryptor basicTextEncryptor = new BasicTextEncryptor();
        basicTextEncryptor.setPasswordCharArray(secret.toCharArray());
        return utf8Slice(basicTextEncryptor.encrypt(privateData.toStringUtf8()));

    }

    @Description("Encrypts a string using AES")
    @ScalarFunction("encryptAES")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice encryptStringAES(@SqlType(StandardTypes.VARCHAR) Slice privateData) {
        AesEncrypt encrypt = null;
        try {
            encrypt = new AesEncrypt(privateData.toStringUtf8(), aesKey);
        }
        catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        assert encrypt != null;
        return utf8Slice(encrypt.getEncryptedStr());
    }

    @Description("Encrypts a binary using AES")
    @ScalarFunction("encryptAES")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice encryptBinaryAES(@SqlType(StandardTypes.VARBINARY) Slice privateData) {
        AesEncrypt encrypt = new AesEncrypt(privateData.toByteBuffer(), aesKey);
        return wrappedBuffer(encrypt.getEncryptedByteBuffer());
    }

    @Description("Decrypts a string using cipher")
    @ScalarFunction("decrypt")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice decryptString(@SqlType(StandardTypes.VARCHAR) Slice secureData) {
        BasicTextEncryptor basicTextEncryptor = new BasicTextEncryptor();
        basicTextEncryptor.setPasswordCharArray(secret.toCharArray());
       return utf8Slice(basicTextEncryptor.decrypt(secureData.toStringUtf8()));

    }

    @Description("Decrypts a string using AES")
    @ScalarFunction("decryptAES")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice decryptStringAES(@SqlType(StandardTypes.VARCHAR) Slice secureData) {
        AesDecrypt decrypt = null;
        try {
            decrypt = new AesDecrypt(secureData.toStringUtf8(), aesKey);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        assert decrypt != null;
        return utf8Slice(decrypt.getDecryptedStr());
    }

    @Description("Decrypts a binary using AES")
    @ScalarFunction("decryptBinaryAES")
    @SqlType(StandardTypes.VARBINARY)
    public static Slice decryptBinaryAES(@SqlType(StandardTypes.VARCHAR) Slice secureData) {
        Base64.Decoder decoder = Base64.getDecoder();
        ByteBuffer data = ByteBuffer.wrap(decoder.decode(secureData.toStringUtf8()));
        AesDecrypt decrypt = new AesDecrypt(data, aesKey);
        return wrappedBuffer(decrypt.getDecryptedByteBuffer());
    }

    @Description("Decrypts a string using cipher and checks for user access")
    @ScalarFunction("decryptuser")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice checkUserToDecrypt(ConnectorSession session, @SqlType(StandardTypes.VARCHAR) Slice secureData) {
        if(
                //Can be integrated with LDAP or other authentication mechanism. Recommended approach is Apache Ranger
                session.getUser().equalsIgnoreCase("admin")
        ){
            BasicTextEncryptor basicTextEncryptor = new BasicTextEncryptor();
            basicTextEncryptor.setPasswordCharArray(secret.toCharArray());
            return utf8Slice(basicTextEncryptor.decrypt(secureData.toStringUtf8()));
        }else {
            throw new AccessDeniedException("You need to be an admin to access secure Data");
        }
    }

    @Description("Decrypts a string using AWS KMS")
    @ScalarFunction("decryptviakms")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice decryptKmsString(@SqlType(StandardTypes.VARBINARY) Slice secureData) {
        DefaultAwsRegionProviderChain creds = new DefaultAwsRegionProviderChain();
        KmsMasterKeyProvider provider = new KmsMasterKeyProvider();
        final AwsCrypto crypto = new AwsCrypto();
        String data = Base64.getEncoder().encodeToString((Base64.getEncoder().encode(secureData.getBytes())));
        final CryptoResult<String, KmsMasterKey> decryptResult  = crypto.decryptString(provider,data);
        return utf8Slice((decryptResult.getResult()));
    }
}
