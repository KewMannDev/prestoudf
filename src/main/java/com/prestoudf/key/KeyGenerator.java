package com.prestoudf.key;

import com.prestoudf.global.Config;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * ==Description==<br/>
 * <p>
 *     Generates java.security.PrivateKey, java.security.PublicKey & javax.crypto.SecretKey (i.e. AES key) objects. <br/>
 *     This class also generates encrypted String of java.security.PrivateKey & java.security.PublicKey in PEM format.
 * </p><br/>
 * ===Objects===<br/>
 * <p>This class contains the following objects when instantiated:</p>
 * <ul>
 *     <li>keyObj</li>
 *     <li>privateKey</li>
 *     <li>publicKey</li>
 *     <li>privateKeyPEMStr</li>
 *     <li>publicKeyPEMStr</li>
 *     <li>aesKey</li>
 *     <li>aesKeySpec</li>
 * </ul>
 * ===Methods===<br/>
 * <p>This class contains the following methods when instantiated:</p>
 * <ul>
 *     <li>KeyGenerator()</li>
 *     <li>keyCreator()</li>
 *     <li>privateKeyPemStrGenerator()</li>
 *     <li>publicKeyPemStrGenerator()</li>
 *     <li>pemStrGenerator(PemObject pemObj)</li>
 *     <li>getPrivateKey()</li>
 *     <li>getPublicKey()</li>
 *     <li>getAesKeySpec()</li>
 *     <li>getAesKey()</li>
 *     <li>getPrivateKeyPEMStr()</li>
 *     <li>setPrivateKeyPEMStr()</li>
 *     <li>getPublicKeyPEMStr()</li>
 *     <li>setPublicKeyPEMStr()</li>
 * </ul>
 *
 * @author Wong Kok-Lim
 */
public class KeyGenerator {
    private static KeyGenerator keyObj = null;

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private String privateKeyPEMStr;
    private String publicKeyPEMStr;
    private SecretKey aesKey;
    private SecretKeySpec aesKeySpec;

    /**
     * Constructor for com.pretoudf.key.KeyGenerator class
     * @return N/A
     * @author Wong Kok-Lim
     */
    private KeyGenerator() {
        Security.addProvider(new BouncyCastleProvider());

        final RSAKeyPairGenerator gen = new RSAKeyPairGenerator();

        gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(10001), new SecureRandom(), 1024, 80));
        final AsymmetricCipherKeyPair keypair = gen.generateKeyPair();

        final RSAKeyParameters publicKeyParam = (RSAKeyParameters) keypair.getPublic();
        final RSAPrivateCrtKeyParameters privateKeyParam = (RSAPrivateCrtKeyParameters) keypair.getPrivate();

        try {
            this.publicKey = KeyFactory.getInstance(Config.RSA_ALGORITHM).generatePublic(new RSAPublicKeySpec(publicKeyParam.getModulus(), publicKeyParam.getExponent()));
            this.privateKey = KeyFactory.getInstance(Config.RSA_ALGORITHM).generatePrivate(new RSAPrivateCrtKeySpec(publicKeyParam.getModulus(), publicKeyParam.getExponent(), privateKeyParam.getExponent(), privateKeyParam.getP(), privateKeyParam.getQ(), privateKeyParam.getDP(), privateKeyParam.getDQ(), privateKeyParam.getQInv()));

            javax.crypto.KeyGenerator kgen = javax.crypto.KeyGenerator.getInstance(Config.AES_ALGORITHM);
            kgen.init(Config.AES_KEY_SIZE);
            this.aesKey = kgen.generateKey();
            byte[] aesKey = this.aesKey.getEncoded();
            this.aesKeySpec = new SecretKeySpec(aesKey, Config.AES_ALGORITHM);
        }
        catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * Calls class constructor to generate java.security.PrivateKey, java.security.PublicKey & javax.crypto.SecretKey (i.e. AES key) objects.
     * @return com.pretoudf.key.KeyGenerator object
     * @author Wong Kok-Lim
     */
    public static KeyGenerator keyCreator() {
        if(keyObj==null){
            keyObj= new KeyGenerator();
        }
        return keyObj;
    }

    /**
     * Converts java.security.PrivateKey to String in encrypted PEM format.
     * @throws OperatorCreationException
     * @throws IOException
     * @return Encrypted String of java.security.PrivateKey in PEM format.
     * @author Wong Kok-Lim
     */
    private void privateKeyPemStrGenerator() throws OperatorCreationException, IOException {
        PKCS8Generator pemGenerator = new PKCS8Generator(PrivateKeyInfo.getInstance(getPrivateKey().getEncoded()), new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC).setProvider(Config.BC_PROVIDER).setPasssword(Config.PASSPHRASE.toCharArray()).build());
        PemObject pemObj = pemGenerator.generate();

        this.privateKeyPEMStr = pemStrGenerator(pemObj);
    }

    /**
     * Converts java.security.PublicKey to String in PEM format.
     * @throws IOException
     * @return Encoded String of java.security.PublicKey in PEM format
     * @author Wong Kok-Lim
     */
    private void publicKeyPemStrGenerator() throws IOException {
        PemObject pemObj = new PemObject("PUBLIC KEY", getPublicKey().getEncoded());

        this.publicKeyPEMStr = pemStrGenerator(pemObj);
    }

    /**
     * Converts org.bouncycastle.util.io.pem.PemObject to String in PEM format.
     * @param pemObj org.bouncycastle.util.io.pem.PemObject object to be converted to String.
     * @return String of org.bouncycastle.util.io.pem.PemObject in PEM format.
     * @throws IOException
     * @author Wong Kok-Lim
     */
    private String pemStrGenerator(PemObject pemObj) throws IOException {
        StringWriter str = new StringWriter();
        PemWriter pemWriter = new PemWriter(str);
        try {
            pemWriter.writeObject(pemObj);
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        finally {
            pemWriter.close();
            str.close();
        }
        return str.toString();
    }

    /**
     * Getter for privateKey object.
     * @return Value of privateKey object.
     * @author Wong Kok-Lim
     */
    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    /**
     * Getter for publicKey object.
     * @return Value of publicKey object.
     * @author Wong Kok-Lim
     */
    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    /**
     * Getter for aesKeySpec object.
     * @return Value of aesKeySpec object.
     * @author Wong Kok-Lim
     */
    public SecretKeySpec getAesKeySpec() {
        return this.aesKeySpec;
    }

    /**
     * Getter for aesKey object.
     * @return Value of aesKey object.
     * @author Wong Kok-Lim
     */
    public SecretKey getAesKey() {
        return this.aesKey;
    }

    /**
     * Getter for privateKeyPEMStr object
     * @return value of privateKeyPEMStr object.
     * @author Wong Kok-Lim
     */
    public String getPrivateKeyPEMStr() {
        return this.privateKeyPEMStr;
    }

    /**
     * Sets value to privateKeyPEMStr object.
     * @author Wong Kok-Lim
     */
    public void setPrivateKeyPEMStr() {
        try {
            privateKeyPemStrGenerator();
        }
        catch (OperatorCreationException | IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Getter for publicKeyPEMStr object.
     * @return value of publicKeyPEMStr object.
     * @author Wong Kok-Lim
     */
    public String getPublicKeyPEMStr() {
        return this.publicKeyPEMStr;
    }

    /**
     * Sets value to publicKeyPEMStr object.
     * @author Wong Kok-Lim
     */
    public void setPublicKeyPEMStr() {
        try {
            publicKeyPemStrGenerator();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }
}
