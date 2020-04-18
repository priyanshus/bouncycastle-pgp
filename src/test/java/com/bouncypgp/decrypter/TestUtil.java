package com.bouncypgp.decrypter;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.logging.Logger;

class TestUtil {

    public InputStream getResource(String path) {
        InputStream inputStream = null;
        try {
            inputStream = new FileInputStream(this.getClass().getClassLoader().getResource(path).getFile());
        } catch (FileNotFoundException e) {
            Logger.getAnonymousLogger().info("No file found at " + path);
        }

        return inputStream;
    }
}
