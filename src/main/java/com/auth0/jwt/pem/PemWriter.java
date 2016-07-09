package com.auth0.jwt.pem;

import org.apache.commons.lang3.Validate;

import java.io.IOException;
import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Write operations for PEM files
 */
public class PemWriter {

    public static void writePrivateKey(final RSAPrivateKey privateKey, final String description, final String filename) throws IOException {
        Validate.notNull(privateKey);
        Validate.notNull(filename);
        writePemFile(privateKey, description, filename);
    }

    public static void writePublicKey(final RSAPublicKey publicKey, final String description, final String filename) throws IOException {
        Validate.notNull(publicKey);
        Validate.notNull(filename);
        writePemFile(publicKey, description, filename);
    }

    public static void writePemFile(final Key key, final String description, final String filename) throws IOException {
        Validate.notNull(key);
        Validate.notNull(filename);
        final PemFileWriter pemFileWriter = new PemFileWriter(key, description);
        pemFileWriter.write(filename);
    }

}
