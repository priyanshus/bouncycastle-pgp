package com.bouncypgp.decrypter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.logging.Logger;

public class KeyUtils {
    public static Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);

    public static PGPSecretKey extractSecretKey(InputStream input)
            throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input),
                new BcKeyFingerprintCalculator());
        Iterator keyRingIter = pgpSec.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();

            Iterator keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                PGPSecretKey key = (PGPSecretKey) keyIter.next();
                if (key.isMasterKey()) {
                    logger.info("Found master Key with id: " + Long.toHexString(key.getKeyID()));
                } else if (key.isSigningKey()) {
                    logger.info("Found signing key with id: " + Long.toHexString(key.getKeyID()));
                    return key;
                }


            }
        }
        throw new PGPException("Can't find signing key in key ring.");
    }

    static PGPPublicKey extractPublicKey(InputStream input) throws PGPException, IOException {
        PGPPublicKey publicKey = null;
        PGPPublicKeyRingCollection pgpPubX = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());
        Iterator rIt = pgpPubX.getKeyRings();

        while (rIt.hasNext()) {
            PGPPublicKeyRing pgpPub = (PGPPublicKeyRing) rIt.next();

            Iterator it = pgpPub.getPublicKeys();
            boolean first = true;
            while (it.hasNext()) {
                PGPPublicKey pgpKey = (PGPPublicKey) it.next();

                if (first) {
                    publicKey = pgpKey;
                    logger.info("Found public key with id: " + Long.toHexString(pgpKey.getKeyID()));
                    first = false;
                } else {
                    logger.info("Found public sub Key with id: " + Long.toHexString(pgpKey.getKeyID()) + " (subkey)");
                }
            }
        }

        return publicKey;
    }

    public static PGPPrivateKey extractPrivateKey(PGPSecretKey pgpSecKey, char[] passPhrase)
            throws PGPException {
        PGPDigestCalculatorProvider calcProvider = new JcaPGPDigestCalculatorProviderBuilder()
                .setProvider(new BouncyCastleProvider()).build();

        PBESecretKeyDecryptor decrypter = new JcePBESecretKeyDecryptorBuilder(
                calcProvider).setProvider(new BouncyCastleProvider())
                .build(passPhrase);
        return pgpSecKey.extractPrivateKey(decrypter);
    }
}
