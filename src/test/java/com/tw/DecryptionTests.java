package com.tw;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

public class DecryptionTests {
    InputStream privateKeyInputStream;
    PGPSecretKey secretKey;
    InputStream publicKeyInputStream;
    PGPPublicKey publicKey;

    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    @Test
    public void decryptSignedEncryptedFileUsingCorrectKeys() throws IOException, PGPException {
        publicKeyInputStream = new FileInputStream(this.getClass().getClassLoader().getResource("john/public-key.txt").getFile());
        privateKeyInputStream = new FileInputStream(this.getClass().getClassLoader().getResource("john/private-key.txt").getFile());

        publicKey  = KeysUtils.extractPublicKey(publicKeyInputStream);
        secretKey = KeysUtils.extractSecretKey(privateKeyInputStream);
        InputStream encryptedFile =  new FileInputStream(this.getClass().getClassLoader().getResource("john/message.txt.asc").getFile());

        String passPhrase = "test@1234";
        SecretKeyConfig secretKeyConfig = new SecretKeyConfig(secretKey, passPhrase);
        Decrypter decrypter = new Decrypter();
        String decryptedData = decrypter
                .givenDecryptionKeys(secretKeyConfig)
                .decrypt(encryptedFile)
                .verifySignatureBy(publicKey)
                .andGetDecryptedDataAsString();

        Assert.assertEquals("hello world\n", decryptedData);
    }

    @Test
    public void decryptAndVerifySignByIncorrectKey() throws IOException, PGPException {
        exceptionRule.expect(org.bouncycastle.openpgp.PGPException.class);
        exceptionRule.expectMessage("Not able to verify one pass signature for b68602a589617d80");

        publicKeyInputStream = new FileInputStream(this.getClass().getClassLoader().getResource("john/some-other-public-key.txt").getFile());
        privateKeyInputStream = new FileInputStream(this.getClass().getClassLoader().getResource("john/private-key.txt").getFile());

        publicKey  = KeysUtils.extractPublicKey(publicKeyInputStream);
        secretKey = KeysUtils.extractSecretKey(privateKeyInputStream);

        InputStream encryptedFile =  new FileInputStream(this.getClass().getClassLoader().getResource("john/message.txt.asc").getFile());
        String passPhrase = "test@1234";
        SecretKeyConfig secretKeyConfig = new SecretKeyConfig(secretKey, passPhrase);
        Decrypter decrypter = new Decrypter();
        decrypter
                .givenDecryptionKeys(secretKeyConfig)
                .decrypt(encryptedFile)
                .verifySignatureBy(publicKey)
                .andGetDecryptedDataAsString();
    }

    @Test
    public void decryptNonArmoredSignedEncryptedFileUsingCorrectKeys() throws IOException, PGPException {
        publicKeyInputStream = new FileInputStream(this.getClass().getClassLoader().getResource("john/public-key.txt").getFile());
        privateKeyInputStream = new FileInputStream(this.getClass().getClassLoader().getResource("john/private-key.txt").getFile());

        publicKey  = KeysUtils.extractPublicKey(publicKeyInputStream);
        secretKey = KeysUtils.extractSecretKey(privateKeyInputStream);

        InputStream encryptedFile =  new FileInputStream(this.getClass().getClassLoader().getResource("john/encrypted.txt").getFile());
        String passPhrase = "test@1234";
        SecretKeyConfig secretKeyConfig = new SecretKeyConfig(secretKey, passPhrase);
        Decrypter decrypter = new Decrypter();
        String decryptedData = decrypter
                .givenDecryptionKeys(secretKeyConfig)
                .decrypt(encryptedFile)
                .verifySignatureBy(publicKey)
                .andGetDecryptedDataAsString();
        Assert.assertEquals("hello world\n", decryptedData);
    }

    @Test
    public void decryptAndVerifyAllSignatures() throws IOException, PGPException {
        publicKeyInputStream = new FileInputStream(this.getClass().getClassLoader().getResource("john/public-key.txt").getFile());
        privateKeyInputStream = new FileInputStream(this.getClass().getClassLoader().getResource("john/private-key.txt").getFile());

        InputStream alicePubIs = new FileInputStream(this.getClass().getClassLoader().getResource("alice/public-key.txt").getFile());
        InputStream alicePriIs = new FileInputStream(this.getClass().getClassLoader().getResource("alice/private-key.txt").getFile());

        publicKey  = KeysUtils.extractPublicKey(publicKeyInputStream);
        secretKey = KeysUtils.extractSecretKey(privateKeyInputStream);

        PGPPublicKey alicePubK  = KeysUtils.extractPublicKey(alicePubIs);
        PGPSecretKey aliceSecretKey = KeysUtils.extractSecretKey(alicePriIs);

        String passPhrase = "test@1234";
        Map<PGPSecretKey, String> keyMap = new HashMap<>();
        keyMap.put(secretKey,passPhrase);
        keyMap.put(aliceSecretKey, passPhrase);

        InputStream encryptedFile =  new FileInputStream(this.getClass().getClassLoader().getResource("john/message.txt.asc").getFile());

        SecretKeyConfig secretKeyConfig = new SecretKeyConfig(keyMap);
        Decrypter decrypter = new Decrypter();
        String decryptedData = decrypter
                .givenDecryptionKeys(secretKeyConfig)
                .decrypt(encryptedFile)
                .verifySignatureBy(publicKey, alicePubK)
                .andGetDecryptedDataAsString();
        Assert.assertEquals("hello world\n", decryptedData);
    }

    @Test
    public void decryptAndFailSignatureVerificationByOneOfTheKey() throws IOException, PGPException {
        exceptionRule.expect(org.bouncycastle.openpgp.PGPException.class);
        exceptionRule.expectMessage("Not able to verify one pass signature for b68602a589617d80");
        publicKeyInputStream = new FileInputStream(this.getClass().getClassLoader().getResource("john/public-key.txt").getFile());
        privateKeyInputStream = new FileInputStream(this.getClass().getClassLoader().getResource("john/private-key.txt").getFile());

        InputStream alicePubIs = new FileInputStream(this.getClass().getClassLoader().getResource("john/some-other-public-key.txt").getFile());
        InputStream alicePriIs = new FileInputStream(this.getClass().getClassLoader().getResource("alice/private-key.txt").getFile());

        publicKey  = KeysUtils.extractPublicKey(publicKeyInputStream);
        secretKey = KeysUtils.extractSecretKey(privateKeyInputStream);

        PGPPublicKey alicePubK  = KeysUtils.extractPublicKey(alicePubIs);
        PGPSecretKey aliceSecretKey = KeysUtils.extractSecretKey(alicePriIs);

        String passPhrase = "test@1234";
        Map<PGPSecretKey, String> keyMap = new HashMap<>();
        keyMap.put(secretKey,passPhrase);
        keyMap.put(aliceSecretKey, passPhrase);

        InputStream encryptedFile =  new FileInputStream(this.getClass().getClassLoader().getResource("john/message.txt.asc").getFile());

        SecretKeyConfig secretKeyConfig = new SecretKeyConfig(keyMap);
        Decrypter decrypter = new Decrypter();
        decrypter
                .givenDecryptionKeys(secretKeyConfig)
                .decrypt(encryptedFile)
                .verifySignatureBy(publicKey, alicePubK)
                .andGetDecryptedDataAsString();
    }

    @Test
    public void decryptAndIgnoreSignatureVerification() throws IOException, PGPException {
        privateKeyInputStream = new FileInputStream(this.getClass().getClassLoader().getResource("john/private-key.txt").getFile());

        secretKey = KeysUtils.extractSecretKey(privateKeyInputStream);
        InputStream encryptedFile =  new FileInputStream(this.getClass().getClassLoader().getResource("john/message.txt.asc").getFile());

        String passPhrase = "test@1234";
        SecretKeyConfig secretKeyConfig = new SecretKeyConfig(secretKey, passPhrase);
        Decrypter decrypter = new Decrypter();
        String decryptedData = decrypter
                .givenDecryptionKeys(secretKeyConfig)
                .decrypt(encryptedFile)
                .ignoreSignVerification()
                .andGetDecryptedDataAsString();

        Assert.assertEquals("hello world\n", decryptedData);
    }

    @Test
    public void decryptWithWrongPrivateKey() throws IOException, PGPException {
        exceptionRule.expect(org.bouncycastle.openpgp.PGPException.class);
        exceptionRule.expectMessage("Not able to decrypt the packets with provided private keys");
        privateKeyInputStream = new FileInputStream(this.getClass().getClassLoader().getResource("john/some-private-key.txt").getFile());

        secretKey = KeysUtils.extractSecretKey(privateKeyInputStream);
        InputStream encryptedFile =  new FileInputStream(this.getClass().getClassLoader().getResource("john/message.txt.asc").getFile());

        String passPhrase = "test@1234";
        SecretKeyConfig secretKeyConfig = new SecretKeyConfig(secretKey, passPhrase);
        Decrypter decrypter = new Decrypter();
        String decryptedData = decrypter
                .givenDecryptionKeys(secretKeyConfig)
                .decrypt(encryptedFile)
                .andGetDecryptedDataAsString();

        Assert.assertEquals("hello world\n", decryptedData);
    }
}
