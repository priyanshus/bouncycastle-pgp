package com.tw;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.junit.*;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

public class DecryptionTests {
    private static TestUtil util;
    private static PGPPublicKey johnPubKey;
    private static PGPSecretKey johnSeckey;
    private static PGPPublicKey alicePubKey;
    private static PGPSecretKey aliceSecKey;
    private static String passPhrase = "test@1234";
    private static Decrypter decrypter;
    private static InputStream multipleSignAndMultipleReceiverEncryptedFile ;
    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    @BeforeClass
    public static void beforeClass() throws PGPException, IOException {
        util = new TestUtil();
        decrypter = new Decrypter();
        johnPubKey = KeyUtils.extractPublicKey(util.getResource("john-keyconfig/john-pub-key.txt"));
        johnSeckey = KeyUtils.extractSecretKey(util.getResource("john-keyconfig/john-sec-key.txt"));

        alicePubKey = KeyUtils.extractPublicKey(util.getResource("alice-keyconfig/alice-pub-key.txt"));
        aliceSecKey = KeyUtils.extractSecretKey(util.getResource("alice-keyconfig/alice-sec-key.txt"));
    }

    @Test
    public void decryptSignedEncryptedFileUsingCorrectKeys() throws IOException, PGPException {
        multipleSignAndMultipleReceiverEncryptedFile = util.getResource("john-keyconfig/multiple-sign-multiple-receiver.asc");
        SecretKeyConfig secretKeyConfig = new SecretKeyConfig(johnSeckey, passPhrase);

        String decryptedData = decrypter
                .givenDecryptionKeys(secretKeyConfig)
                .decrypt(multipleSignAndMultipleReceiverEncryptedFile)
                .verifySignatureBy(johnPubKey)
                .andGetDecryptedDataAsString();

        Assert.assertEquals("hello world\n", decryptedData);
    }

    @Test
    public void decryptAndVerifySignByIncorrectKey() throws IOException, PGPException {
        exceptionRule.expect(org.bouncycastle.openpgp.PGPException.class);
        exceptionRule.expectMessage("Not able to verify one pass signature for b68602a589617d80");

        multipleSignAndMultipleReceiverEncryptedFile = util.getResource("john-keyconfig/multiple-sign-multiple-receiver.asc");
        PGPPublicKey somePublicKey = KeyUtils.extractPublicKey(util.getResource("some-other-keyconfig/some-pub-key.txt"));
        SecretKeyConfig secretKeyConfig = new SecretKeyConfig(johnSeckey, passPhrase);

        decrypter
                .givenDecryptionKeys(secretKeyConfig)
                .decrypt(multipleSignAndMultipleReceiverEncryptedFile)
                .verifySignatureBy(somePublicKey)
                .andGetDecryptedDataAsString();
    }

    @Test
    public void decryptSingleSignedEncryptedFileUsingCorrectKey() throws IOException, PGPException {
        InputStream encryptedFile = util.getResource("john-keyconfig/single-sign-receiver-encrypted.txt");
        SecretKeyConfig secretKeyConfig = new SecretKeyConfig(johnSeckey, passPhrase);
        String decryptedData = decrypter
                .givenDecryptionKeys(secretKeyConfig)
                .decrypt(encryptedFile)
                .verifySignatureBy(johnPubKey)
                .andGetDecryptedDataAsString();
        Assert.assertEquals("hello world\n", decryptedData);
    }

    @Test
    public void decryptAndVerifyAllSignatures() throws IOException, PGPException {
        multipleSignAndMultipleReceiverEncryptedFile = util.getResource("john-keyconfig/multiple-sign-multiple-receiver.asc");
        Map<PGPSecretKey, String> keyMap = new HashMap<>();
        keyMap.put(johnSeckey, passPhrase);
        keyMap.put(aliceSecKey, passPhrase);
        SecretKeyConfig secretKeyConfig = new SecretKeyConfig(keyMap);
        String decryptedData = decrypter
                .givenDecryptionKeys(secretKeyConfig)
                .decrypt(multipleSignAndMultipleReceiverEncryptedFile)
                .verifySignatureBy(johnPubKey, alicePubKey)
                .andGetDecryptedDataAsString();
        Assert.assertEquals("hello world\n", decryptedData);
    }

    @Test
    public void decryptAndFailSignatureVerificationByOneOfTheKey() throws IOException, PGPException {
        multipleSignAndMultipleReceiverEncryptedFile = util.getResource("john-keyconfig/multiple-sign-multiple-receiver.asc");
        exceptionRule.expect(org.bouncycastle.openpgp.PGPException.class);
        exceptionRule.expectMessage("Not able to verify one pass signature for b68602a589617d80");

        Map<PGPSecretKey, String> keyMap = new HashMap<>();
        keyMap.put(johnSeckey, passPhrase);
        keyMap.put(aliceSecKey, passPhrase);
        PGPPublicKey somePublicKey = KeyUtils.extractPublicKey(util.getResource("some-other-keyconfig/some-pub-key.txt"));

        SecretKeyConfig secretKeyConfig = new SecretKeyConfig(keyMap);
        decrypter
                .givenDecryptionKeys(secretKeyConfig)
                .decrypt(multipleSignAndMultipleReceiverEncryptedFile)
                .verifySignatureBy(somePublicKey, alicePubKey)
                .andGetDecryptedDataAsString();
    }

    @Test
    public void decryptAndIgnoreSignatureVerification() throws IOException, PGPException {
        InputStream encryptedFile = util.getResource("john-keyconfig/multiple-sign-multiple-receiver.asc");

        SecretKeyConfig secretKeyConfig = new SecretKeyConfig(johnSeckey, passPhrase);
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
        InputStream inputStream = util.getResource("some-other-keyconfig/some-sec-key.txt");

        PGPSecretKey someSecKey = KeyUtils.extractSecretKey(inputStream);
        InputStream encryptedFile = util.getResource("john-keyconfig/multiple-sign-multiple-receiver.asc");

        SecretKeyConfig secretKeyConfig = new SecretKeyConfig(someSecKey, passPhrase);

        String decryptedData = decrypter
                .givenDecryptionKeys(secretKeyConfig)
                .decrypt(encryptedFile)
                .andGetDecryptedDataAsString();

        Assert.assertEquals("hello world\n", decryptedData);
    }
}
