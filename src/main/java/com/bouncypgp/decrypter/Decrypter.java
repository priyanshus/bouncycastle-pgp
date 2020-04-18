package com.tw;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

public class Decrypter {
    public Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
    public BcKeyFingerprintCalculator fingerPrintCalculator = new BcKeyFingerprintCalculator();
    private SecretKeyConfig secretKeyConfig;
    private InputStream encryptedInputStream;
    private Validator validator;
    private boolean signVerification = false;
    private String decryptedData;

    public Decrypter givenDecryptionKeys(SecretKeyConfig secretKeyConfig) {
        this.secretKeyConfig = secretKeyConfig;
        return this;
    }

    /**
     * Decrypts a given input stream (file) which is signed and encrypted by pgp CLI as below: <br>
     * <code>gpg --encrypt --sign --armor --output encrypted-signed-output.txt -r <receiver-mail-id> inputfile.txt</code>
     *
     * @param inputStream InputStream for the file for which decryption needs to be performed
     * @throws IOException
     * @throws PGPException
     */
    private String decryptGivenStream(InputStream inputStream) throws IOException, PGPException {
        InputStream plainText = null;
        List<PGPOnePassSignature> verifiedOnePassSignatures = null;
        inputStream = PGPUtil.getDecoderStream(inputStream);
        PGPObjectFactory objectFactory = new PGPObjectFactory(inputStream, fingerPrintCalculator);
        Object object = objectFactory.nextObject();

        if(object instanceof PGPEncryptedDataList) {
            logger.info("Found Encrypted Data List");
            PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) object;

            if (encryptedDataList.isEmpty()) {
                throw new PGPException("Decryption failed - No encrypted data found!");
            }else {
                plainText = getPlainTextFromEncryptedDataList(encryptedDataList, secretKeyConfig.getSecretKeys());
            }

            objectFactory = new PGPObjectFactory(plainText, new BcKeyFingerprintCalculator());
            object = objectFactory.nextObject();
        }else {
            throw new PGPException("Not able to find encrypted data list");
        }

        if (object instanceof PGPCompressedData) {
            logger.info("Found PGP Compressed Data");
            byte[] compressedBytes = ((PGPCompressedData) object).getDataStream().readAllBytes();
            objectFactory = new PGPObjectFactory(compressedBytes, fingerPrintCalculator);
            object = objectFactory.nextObject();
        } else {
            throw new PGPException("Not able to find Compressed Data packet");
        }

        if (object instanceof PGPOnePassSignatureList) {
            logger.info("Found PGP OnePass Signature List");
            PGPOnePassSignatureList onePassSignatures = (PGPOnePassSignatureList) object;
            verifiedOnePassSignatures = new ArrayList<>();

            if(signVerification) {
                verifiedOnePassSignatures = validator.verifyOnePassSignatureKeyId(onePassSignatures);
            }

            if(verifiedOnePassSignatures.isEmpty() && signVerification) {
                throw new PGPException("Not able to verify any of the one pass signatures");
            }else {
                object = (PGPLiteralData)objectFactory.nextObject();
            }
        }else {
            throw new PGPException("Not able to find OnePass Signature List");
        }

        if (object instanceof PGPLiteralData) {
            logger.info("Found PGP Literal Data");
            InputStream literalDataInputStream = ((PGPLiteralData) object).getInputStream();
            byte[] bytes = pipe(literalDataInputStream);

            if(signVerification) {
                PGPSignatureList signatureList = (PGPSignatureList) objectFactory.nextObject();

                List<PGPSignature> verifiedSigns = validator.verifySignaturePackets(bytes, verifiedOnePassSignatures, signatureList);

                if (verifiedSigns.isEmpty()) {
                    throw new PGPException("Not able to verify any of the signature packets");
                } else if (verifiedOnePassSignatures.size() == verifiedSigns.size()) {
                    decryptedData =  new String(bytes);
                    return decryptedData;
                }
            }else {
                decryptedData =  new String(bytes);
                return decryptedData;
            }
        }

        throw new PGPException("Not able to decrypt the file");
    }

    private InputStream getPlainTextFromEncryptedDataList(PGPEncryptedDataList dataList, Map<PGPSecretKey, String> keymap) throws PGPException {
        final Iterator<?> encryptedDataObjects = dataList.getEncryptedDataObjects();
        while (encryptedDataObjects.hasNext()) {
            PGPPublicKeyEncryptedData encryptedData = (PGPPublicKeyEncryptedData) encryptedDataObjects.next();

            for(PGPSecretKey secretKey: keymap.keySet()) {
                PGPPrivateKey privateKey = KeyUtils.extractPrivateKey(secretKey, keymap.get(secretKey).toCharArray());
                try {
                    InputStream plainText = encryptedData.getDataStream(new BcPublicKeyDataDecryptorFactory(
                            privateKey));
                    logger.info("Found Plain Text from Encrypted Data List");
                    return plainText;
                }catch (PGPException e) {
                }
            }
        }
        throw new PGPException("Not able to decrypt the packets with provided private keys");
    }

    public Decrypter ignoreSignVerification() {
        this.signVerification = false;
        return this;
    }

    public String andGetDecryptedDataAsString() throws IOException, PGPException {
        String decryptedData =  decryptGivenStream(encryptedInputStream);
        return decryptedData;
    }

    public Decrypter verifySignatureBy(PGPPublicKey...publicKeys) {
        this.signVerification = true;
        PublicKeyConfig publicKeyConfig = new PublicKeyConfig(publicKeys);
        validator = new Validator(publicKeyConfig);
        return this;
    }

    public Decrypter decrypt(InputStream inputStream) {
        this.encryptedInputStream = inputStream;
        return this;
    }

    private byte[] pipe(InputStream is) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Streams.pipeAll(is, bos);
        bos.close();
        return bos.toByteArray();
    }
}
