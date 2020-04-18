package com.bouncypgp.decrypter;

import org.bouncycastle.openpgp.PGPPublicKey;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

public class PublicKeyConfig {
    private List<PGPPublicKey> keys = new ArrayList<>();

    public PublicKeyConfig(PGPPublicKey...publicKeys) {
        for (PGPPublicKey key: publicKeys) {
            keys.add(key);
        }
    }

    public List<PGPPublicKey> getPublicKeys() {
        return keys;
    }
}
