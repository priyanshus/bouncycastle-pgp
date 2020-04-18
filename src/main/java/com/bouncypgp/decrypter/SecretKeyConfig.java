package com.bouncypgp.decrypter;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SecretKeyConfig {
    private Map<PGPSecretKey, String> secretKeys = new HashMap<>();

    public SecretKeyConfig(Map<PGPSecretKey, String> secretKeysMap) {
        this.secretKeys = secretKeysMap;
    }

    public SecretKeyConfig(PGPSecretKey secretKeys, String passPhrase) {
        this.secretKeys.put(secretKeys, passPhrase);
    }

    public Map<PGPSecretKey, String> getSecretKeys() {
        return secretKeys;
    }

}
