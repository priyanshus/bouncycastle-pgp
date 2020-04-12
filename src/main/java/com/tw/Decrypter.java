package com.tw;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

public class Decrypter {
    /**
     * Decrypts a given input stream (file) which is signed and encrypted by pgp CLI as below: <br>
     * <code>gpg --encrypt --sign --armor --output encrypted-signed-output.txt -r <receiver-mail-id> inputfile.txt</code>
     *
     * @param inputStream InputStream for the file for which decryption needs to be performed
     * @param secretKey PGPSecretKey - The private key by which decryption needs to be done
     * @param publicKey PGPPublicKey - The public key by which signing needs to be verified
     * @param password String - The passphrase by which Private key is protected
     * @throws IOException
     * @throws PGPException
     */
    public static String decrypt(InputStream inputStream, PGPSecretKey secretKey, PGPPublicKey publicKey, String password) throws IOException, PGPException {
        PGPOnePassSignature onePassSignature = null;
        PGPPublicKeyEncryptedData encryptedData = null;
        char[] passPhrase = password.toCharArray();

        inputStream = PGPUtil.getDecoderStream(inputStream);
        PGPObjectFactory objectFactory = new PGPObjectFactory(inputStream, new BcKeyFingerprintCalculator());
        Object object = objectFactory.nextObject();
        if (object instanceof PGPEncryptedDataList) {
            System.out.println("Found PGPEncryptedDataList Packet");
            PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) object;
            final Iterator<?> encryptedDataObjects = encryptedDataList.getEncryptedDataObjects();
            if (!encryptedDataObjects.hasNext()) {
                throw new PGPException("Decryption failed - No encrypted data found!");
            }
            PGPPrivateKey privateKey = null;
            encryptedData = null;
            while (privateKey == null && encryptedDataObjects.hasNext()) {
                encryptedData = (PGPPublicKeyEncryptedData) encryptedDataObjects.next();
                privateKey = extractPrivateKey(secretKey, passPhrase);
            }

            if (privateKey == null) {
                throw new PGPException(
                        "Decryption failed - No secret key was found in the key ring matching the public key"
                                + " used to encrypt the file, aborting");
            }

            InputStream plainText = encryptedData
                    .getDataStream(new BcPublicKeyDataDecryptorFactory(
                            privateKey));
            objectFactory = new PGPObjectFactory(plainText, new BcKeyFingerprintCalculator());
            object = objectFactory.nextObject();
        } else {
            throw new PGPException(
                    "Decryption failed - Not able to find encrypted Data list");
        }

        if (object instanceof PGPCompressedData) {
            System.out.println("Found PGPCompressed Packet");
            objectFactory = new PGPObjectFactory(
                    ((PGPCompressedData) object).getDataStream(), new BcKeyFingerprintCalculator());
            object = objectFactory.nextObject();
        } else {
            throw new PGPException(
                    "Decryption failed - Not able to find Compressed Data packet");
        }

        if (object instanceof PGPOnePassSignatureList) {
            System.out.println("Found PGPOnePassSignatureList packet");
            PGPOnePassSignatureList onePassSignatures = (PGPOnePassSignatureList) object;
            System.out.println("No of one pass signatures available:" + onePassSignatures.size());
            if (onePassSignatures.size() == 1) {
                onePassSignature = onePassSignatures.get(0);
                onePassSignature.init(new BcPGPContentVerifierBuilderProvider(), publicKey);
                System.out.println("One Pass Signature :" + Long.toHexString(onePassSignature.getKeyID()));
                System.out.println("Public Key Id :" + Long.toHexString(publicKey.getKeyID()));

                if (onePassSignature.getKeyID() == publicKey.getKeyID()) {
                    System.out.println("Signature Key ID verified");
                } else {
                    System.out.println("Signature could not verify");
                }
                object = (PGPLiteralData) objectFactory.nextObject();
            } else {
                throw new PGPException(
                        "Decryption failed - Multiple OnePass Signatures Found");
            }
        } else {
            throw new PGPException(
                    "Decryption failed - Not able to find OnePassSignature PacketList");
        }

        if (object instanceof PGPLiteralData) {
            System.out.println("Found PGPLiteral Data Packet");
            PGPLiteralData literalData = (PGPLiteralData) object;
            if (encryptedData.isIntegrityProtected()) {
                if (!encryptedData.verify()) {
                    throw new PGPException("Failed at Integrity check");
                }
            }
            InputStream literalDataInputStream = literalData.getInputStream();
            byte[] bytes = literalDataInputStream.readAllBytes();
            onePassSignature.update(bytes);
            PGPSignatureList signatureList = (PGPSignatureList) objectFactory.nextObject();

            if (onePassSignature.verify(signatureList.get(0))) {
                String decryptedData = new String(bytes, StandardCharsets.UTF_8);
                System.out.println("Signature verified");
                System.out.println("The decrypted data: " + decryptedData);
                return decryptedData;
            } else {
                throw new PGPException("Signature verification failed!");
            }
        }

        throw new PGPException("Not able to decrypt the file");
    }

    static PGPPrivateKey extractPrivateKey(PGPSecretKey pgpSecKey, char[] passPhrase)
            throws PGPException {
        PGPDigestCalculatorProvider calcProvider = new JcaPGPDigestCalculatorProviderBuilder()
                .setProvider(new BouncyCastleProvider()).build();

        PBESecretKeyDecryptor decrypter = new JcePBESecretKeyDecryptorBuilder(
                calcProvider).setProvider(new BouncyCastleProvider())
                .build(passPhrase);
        return pgpSecKey.extractPrivateKey(decrypter);
    }
}
