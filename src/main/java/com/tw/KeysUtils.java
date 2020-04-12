package com.tw;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

public class KeysUtils {
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
                    System.out.println("Found master Key with id: " + Long.toHexString(key.getKeyID()));
                } else if (key.isSigningKey()) {
                    System.out.println("Found signing key with id: " + Long.toHexString(key.getKeyID()));
                    return key;
                }


            }
        }
        throw new IllegalArgumentException(
                "Can't find signing key in key ring.");
    }

    static PGPPublicKey extractPublicKey(InputStream input) throws PGPException, IOException {
        PGPPublicKey publicKey = null;
        PGPPublicKeyRingCollection pgpPubX = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());
        System.out.println(pgpPubX.size());
        Iterator rIt = pgpPubX.getKeyRings();

        while (rIt.hasNext()) {
            PGPPublicKeyRing pgpPub = (PGPPublicKeyRing) rIt.next();

            Iterator it = pgpPub.getPublicKeys();
            boolean first = true;
            while (it.hasNext()) {
                PGPPublicKey pgpKey = (PGPPublicKey) it.next();

                if (first) {
                    publicKey = pgpKey;
                    System.out.println("Found public key with id: " + Long.toHexString(pgpKey.getKeyID()));
                    first = false;
                } else {
                    System.out.println("Found public sub Key with id: " + Long.toHexString(pgpKey.getKeyID()) + " (subkey)");
                }
            }
        }

        return publicKey;
    }
}
