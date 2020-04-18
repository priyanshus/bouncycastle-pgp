# bouncycastle-pgp
Bouncycastle based pgp decryption
[![Build Status](https://travis-ci.org/priyanshus/bouncycastle-pgp.svg?branch=master)](https://travis-ci.org/github/priyanshus/bouncycastle-pgp)

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

###
JDK Support
  - oraclejdk11
  - openjdk10
  - openjdk11
  
##
WORK IN PROGRESS...