# bouncycastle-pgp
Bouncycastle based pgp decryption

## How to decrypt
Supports signature verification for multiple signature packets.

```java
String decryptedData = decrypter
                .givenDecryptionKeys(secretKeyConfig)
                .decrypt(encryptedFile)
                .verifySignatureBy(bobPublicKey, alicePublicKey) 
                .andGetDecryptedDataAsString();
```
[Examples](https://github.com/priyanshus/bouncycastle-pgp/blob/master/src/test/java/com/tw/DecryptionTests.java)

##
WORK IN PROGRESS...

###
Support for JDK-11