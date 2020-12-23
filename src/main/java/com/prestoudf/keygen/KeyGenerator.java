package com.prestoudf.keygen;

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
import org.bouncycastle.util.io.pem.PemGenerationException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * ==Description==
 * <p>
 * <p>
 * ===Objects===
 * This class contains the following objects when instantiated:
 * -
 * <p>
 * ===Methods===
 * This class contains the following methods when instantiated:
 * -
 *
 * @author koklim
 * @example
 */
public class KeyGenerator {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private String privateKeyPEM;

    private KeyGenerator() {
        Security.addProvider(new BouncyCastleProvider());

        final RSAKeyPairGenerator gen = new RSAKeyPairGenerator();

        gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(10001), new SecureRandom(), 1024, 80));
        final AsymmetricCipherKeyPair keypair = gen.generateKeyPair();

        final RSAKeyParameters publicKeyParam = (RSAKeyParameters) keypair.getPublic();
        final RSAPrivateCrtKeyParameters privateKeyParam = (RSAPrivateCrtKeyParameters) keypair.getPrivate();

        try {
            this.publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(publicKeyParam.getModulus(), publicKeyParam.getExponent()));
            this.privateKey = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(publicKeyParam.getModulus(), publicKeyParam.getExponent(), privateKeyParam.getExponent(), privateKeyParam.getP(), privateKeyParam.getQ(), privateKeyParam.getDP(), privateKeyParam.getDQ(), privateKeyParam.getQInv()));
        }
        catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private void pemGenerator() throws OperatorCreationException, IOException {
        PKCS8Generator pemGenerator = new PKCS8Generator(PrivateKeyInfo.getInstance(getPrivateKey().getEncoded()), new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC).setProvider("BC").setPasssword("test".toCharArray()).build());
        PemObject pemObj = pemGenerator.generate();
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

        this.privateKeyPEM = str.toString();
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getPrivateKeyPEM() {
        return privateKeyPEM;
    }
}
