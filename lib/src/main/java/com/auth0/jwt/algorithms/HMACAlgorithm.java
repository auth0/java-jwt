package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;

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
    public void verify(byte[] contentBytes, byte[] signatureBytes) throws SignatureVerificationException {
        try {
            boolean valid = crypto.verifyMacFor(getDescription(), secret.getBytes(), contentBytes, signatureBytes);

            if (!valid) {
                throw new SignatureVerificationException(this);
            }
        } catch (IllegalStateException | InvalidKeyException | NoSuchAlgorithmException e) {
            throw new SignatureVerificationException(this, e);
        }
    }

    @Override
    public byte[] sign(byte[] contentBytes) throws SignatureGenerationException {
        try {
            return crypto.createMacFor(getDescription(), secret.getBytes(), contentBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new SignatureGenerationException(this, e);
        }
    }

}
