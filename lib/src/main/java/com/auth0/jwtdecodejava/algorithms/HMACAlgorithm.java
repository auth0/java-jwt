package com.auth0.jwtdecodejava.algorithms;

import com.auth0.jwtdecodejava.exceptions.SignatureVerificationException;
import org.apache.commons.codec.binary.Base64;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

class HMACAlgorithm extends Algorithm {

    private final CryptoHelper crypto;
    private final String secret;

    HMACAlgorithm(CryptoHelper crypto, String id, String algorithm, String secret) {
        super(id, algorithm);
        if (secret == null) {
            throw new IllegalArgumentException("The Secret cannot be null");
        }
        this.secret = secret;
        this.crypto = crypto;
    }

    HMACAlgorithm(String id, String algorithm, String secret) {
        this(new CryptoHelper(), id, algorithm, secret);
    }

    String getSecret() {
        return secret;
    }

    @Override
    public void verify(String[] jwtParts) throws SignatureVerificationException {
        try {
            String message = String.format("%s.%s", jwtParts[0], jwtParts[1]);
            byte[] signature = Base64.decodeBase64(jwtParts[2]);
            boolean valid = crypto.verifyMacFor(getDescription(), secret.getBytes(), message.getBytes(), signature);

            if (!valid) {
                throw new SignatureVerificationException(this);
            }
        } catch (IllegalStateException | InvalidKeyException | NoSuchAlgorithmException e) {
            throw new SignatureVerificationException(this, e);
        }
    }

}
