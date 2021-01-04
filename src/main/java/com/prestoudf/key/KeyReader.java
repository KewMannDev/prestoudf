package com.prestoudf.key;

import com.prestoudf.global.Config;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;

/**
 * ==Description==
 * <p>
 *     Decrypt and read java.security.PrivateKey, java.security.PublicKey & javax.crypto.SecretKey (i.e. AES key) objects from file.
 * <p>
 * ===Objects===
 * <p>This class does not contain any objects when instantiated.</p>
 *
 * ===Methods===
 * <p>This class contains the following methods when instantiated:</p>
 * <ul>
 *     <li>KeyReader()</li>
 *     <li>readKeyPairFile()</li>
 *     <li>getPrivateKey()</li>
 *     <li>getPublicKey()</li>
 *     <li>loadKey(PrivateKey pk)</li>
 *     <li>readPemFile(String path)</li>
 * </ul>
 *
 * @author Wong Kok-Lim
 * @example
 */
public class KeyReader {
    /**
     * Constructor for KeyReader class.
     * @author Wong Kok-Lim
     */
    public KeyReader(){
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     * Decrypts openssl generated PEM file and generates java.security.KeyPair.
     * @return java.security.KeyPair object after decrypting openssl generated PEM file.
     * @throws IOException
     * @author Wong Kok-Lim
     */
    public KeyPair readKeyPairFile() throws IOException {
        KeyPair result = null;

        try {
            Object pemobj = readPemFile(Config.PRIVATEKEY_PATH);
            if (pemobj == null || !((pemobj instanceof PEMKeyPair) || (pemobj instanceof PEMEncryptedKeyPair))) {
                System.out.println("Unable to read key pair");
            }
            else {
                PEMKeyPair pemkp;
                if (pemobj instanceof PEMEncryptedKeyPair) {
                    PEMEncryptedKeyPair kp = (PEMEncryptedKeyPair)pemobj;
                    PEMDecryptorProvider decprov = new BcPEMDecryptorProvider(Config.PASSPHRASE.toCharArray());
                    pemkp = kp.decryptKeyPair(decprov);
                }
                else {
                    pemkp = (PEMKeyPair)pemobj;
                }
                result = new JcaPEMKeyConverter().setProvider(Config.BC_PROVIDER).getKeyPair(pemkp);
                System.out.println(result.getPrivate());
                System.out.println(result.getPublic());
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        }

        return result;
    }

    /**
     * Decrypts and reads private key PEM file.
     * @return java.security.PrivateKey object.
     * @throws IOException
     * @author Wong Kok-Lim
     */
    public PrivateKey getPrivateKey() throws IOException {
        PrivateKey result = null;

        try {
            Object pemobj = readPemFile(Config.PRIVATEKEY_PATH);
            if (pemobj == null || !(pemobj instanceof PKCS8EncryptedPrivateKeyInfo)) {
                System.out.println("Unable to read private key PEM");
            }
            else {
                if (pemobj instanceof PKCS8EncryptedPrivateKeyInfo) {
                    PKCS8EncryptedPrivateKeyInfo pk = (PKCS8EncryptedPrivateKeyInfo) pemobj;
                    JcaPEMKeyConverter pemKeyConverter = new JcaPEMKeyConverter().setProvider(Config.BC_PROVIDER);
                    InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder().setProvider(Config.BC_PROVIDER).build(Config.PASSPHRASE.toCharArray());
                    result = pemKeyConverter.getPrivateKey(pk.decryptPrivateKeyInfo(inputDecryptorProvider));
                }
            }
        }
        catch (IOException | PKCSException e) {
            e.printStackTrace();
        }

        return result;
    }

    /**
     * Decode and read public key PEM file.
     * @return java.security.PublicKey object.
     * @throws IOException
     * @author Wong Kok-Lim
     */
    public PublicKey getPublicKey() throws IOException {
        PublicKey result = null;

        try {
            Object pemobj = readPemFile(Config.PUBLICKEY_PATH);
            if (pemobj == null || !(pemobj instanceof SubjectPublicKeyInfo)) {
                System.out.println("Unable to read public key PEM");
            }
            else {
                if (pemobj instanceof SubjectPublicKeyInfo) {
                    SubjectPublicKeyInfo pk = (SubjectPublicKeyInfo)pemobj;
                    JcaPEMKeyConverter pemKeyConverter = new JcaPEMKeyConverter().setProvider(Config.BC_PROVIDER);
                    result = pemKeyConverter.getPublicKey(pk);
                }
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        }

        return result;
    }

    /**
     * Decrypt and read AES key from file.
     * @param pk java.security.PrivateKey to use for decryption.
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IOException
     * @author Wong Kok-Lim
     */
    public SecretKey loadKey(PrivateKey pk) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        Cipher pkCipher = Cipher.getInstance(Config.RSA_ALGORITHM);
        // read AES key
        pkCipher.init(Cipher.DECRYPT_MODE, pk);
        byte[] aesKey = new byte[Config.AES_KEY_SIZE/8];
        CipherInputStream is = new CipherInputStream(new FileInputStream(Config.AESKEY_PATH), pkCipher);
        is.read(aesKey);
        return new SecretKeySpec(aesKey, Config.AES_ALGORITHM);
    }

    /**
     * Reads PEM files and returns PEM object.
     * @param path Location of PEM file.
     * @return java.lang.Object
     * @throws IOException
     */
    private Object readPemFile(String path) throws IOException {
        FileReader reader = new FileReader(path);
        PEMParser parser = new PEMParser(reader);
        Object pemobj = null;
        try {
            pemobj = parser.readObject();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        finally {
            parser.close();
            reader.close();
        }
        return pemobj;
    }
}
