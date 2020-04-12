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

public class DecryptionTests {
    InputStream privateKeyInputStream;
    PGPSecretKey secretKey;
    InputStream publicKeyInputStream;
    PGPPublicKey publicKey;

    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    // Test to verify signature and decryption using correct key combinatoion
    // The input provided to this test is signed and encrypted as below command
    // gpg --encrypt --sign --armor --output encrypted.txt -r john@mail.com message.txt
    // the encryption is done using john@mail.com public key and signing is done by john@mail.com private key
    // In order to decrypt the john's private key is used
    // To verify the signature john's public key is used
    @Test
    public void decryptSignedEncryptedFileUsingCorrectKeys() throws IOException, PGPException {
        publicKeyInputStream = new FileInputStream(this.getClass().getClassLoader().getResource("john/public-key.txt").getFile());
        privateKeyInputStream = new FileInputStream(this.getClass().getClassLoader().getResource("john/private-key.txt").getFile());

        publicKey  = KeysUtils.extractPublicKey(publicKeyInputStream);
        secretKey = KeysUtils.extractSecretKey(privateKeyInputStream);

        InputStream encryptedFile =  new FileInputStream(this.getClass().getClassLoader().getResource("john/encrypted-armor.txt").getFile());
        String passPhrase = "test@1234";
        String decryptedData = Decrypter.decrypt(encryptedFile,secretKey,publicKey, passPhrase);
        Assert.assertEquals("hello world\n", decryptedData);
    }

    // Similar to above test
    // Decryption is done John's private key
    // However, signing is verified by some other public key which should fail the test
    @Test
    public void decryptSignedEncryptedFileUsingIncorrectSigningKey() throws IOException, PGPException {
        exceptionRule.expect(org.bouncycastle.openpgp.PGPException.class);
        exceptionRule.expectMessage("Signature verification failed!");

        publicKeyInputStream = new FileInputStream(this.getClass().getClassLoader().getResource("john/some-other-public-key.txt").getFile());
        privateKeyInputStream = new FileInputStream(this.getClass().getClassLoader().getResource("john/private-key.txt").getFile());

        publicKey  = KeysUtils.extractPublicKey(publicKeyInputStream);
        secretKey = KeysUtils.extractSecretKey(privateKeyInputStream);

        InputStream encryptedFile =  new FileInputStream(this.getClass().getClassLoader().getResource("john/encrypted-armor.txt").getFile());
        String passPhrase = "test@1234";
        String decryptedData = Decrypter.decrypt(encryptedFile,secretKey,publicKey, passPhrase);
    }

    @Test
    public void decryptNonArmoredSignedEncryptedFileUsingCorrectKeys() throws IOException, PGPException {
        publicKeyInputStream = new FileInputStream(this.getClass().getClassLoader().getResource("john/public-key.txt").getFile());
        privateKeyInputStream = new FileInputStream(this.getClass().getClassLoader().getResource("john/private-key.txt").getFile());

        publicKey  = KeysUtils.extractPublicKey(publicKeyInputStream);
        secretKey = KeysUtils.extractSecretKey(privateKeyInputStream);

        InputStream encryptedFile =  new FileInputStream(this.getClass().getClassLoader().getResource("john/encrypted.txt").getFile());
        String passPhrase = "test@1234";
        String decryptedData = Decrypter.decrypt(encryptedFile,secretKey,publicKey, passPhrase);
        Assert.assertEquals("hello world\n", decryptedData);
    }

}
