package com.prestoudf.key;

import com.prestoudf.global.Config;
import org.bouncycastle.jcajce.io.CipherOutputStream;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

/**
 * ==Description==
 * <p>
 *     This class writes java.security.PrivateKey, java.security.PublicKey & javax.crypto.SecretKey (i.e. AES key) objects to file.
 * </p>
 * ===Objects===
 * <p>This class does not contain any objects when instantiated.</p>
 *
 * ===Methods===
 * <p>This class contains the following methods when instantiated:</p>
 * <ul>
 *     <li>KeyWriter</li>
 *     <li>saveAESKey(SecretKey aesKey, PublicKey publicKey)</li>
 *     <li>savePrivateKeyPem(String pemString)</li>
 *     <li>savePubliceKeyPem(String pemString)</li>
 *     <li>savePem(String pemString, String path)</li>
 * </ul>
 *
 * @author Wong Kok-Lim
 * @example
 */
public class KeyWriter {
    /**
     * Constructor for KeyWriter class.
     * @author Wong Kok-Lim
     */
    public KeyWriter() {
    }

    /**
     * Encrypts and writes javax.crypto.SecretKey (i.e. AES key) to file.
     * @param aesKey javax.crypto.SecretKey (i.e. AES key) to be encryted and written to file.
     * @param publicKey java.security.PublicKey to be used for encryption.
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @author Wong Kok-Lim
     */
    public void saveAESKey(SecretKey aesKey, PublicKey publicKey) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher pkCipher = Cipher.getInstance(Config.RSA_ALGORITHM);

        pkCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        try (CipherOutputStream os = new CipherOutputStream(new FileOutputStream(Config.AESKEY_PATH), pkCipher)) {
            os.write(aesKey.getEncoded());
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Writes given PEM format String to file in specified path for private key.
     * @param pemString PEM format String to be written to file.
     * @author Wong Kok-Lim
     */
    public void savePrivateKeyPem(String pemString) {
        savePem(pemString, Config.PRIVATEKEY_PATH);
    }

    /**
     * Writes given PEM format String to file in specified path for public key.
     * @param pemString PEM format String to be written to file.
     * @author Wong Kok-Lim
     */
    public void savePubliceKeyPem(String pemString) {
        savePem(pemString, Config.PUBLICKEY_PATH);
    }

    /**
     * Writes given PEM format String to file in specified path.
     * @param pemString PEM format String to be written to file.
     * @param path Path to write file in.
     * @author Wong Kok-Lim
     */
    private void savePem(String pemString, String path) {
        try (PrintWriter pw = new PrintWriter(new FileOutputStream(path))) {
            pw.print(pemString);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}
