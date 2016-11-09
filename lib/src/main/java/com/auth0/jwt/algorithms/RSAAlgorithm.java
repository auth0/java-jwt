package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;

import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

class RSAAlgorithm extends Algorithm {

    private final RSAKey key;
    private final CryptoHelper crypto;

    RSAAlgorithm(CryptoHelper crypto, String id, String algorithm, RSAKey key) {
        super(id, algorithm);
        if (key == null) {
            throw new IllegalArgumentException("The RSAKey cannot be null");
        }
        this.key = key;
        this.crypto = crypto;
    }

    RSAAlgorithm(String id, String algorithm, RSAKey key) {
        this(new CryptoHelper(), id, algorithm, key);
    }

    RSAKey getKey() {
        return key;
    }

    @Override
    public void verify(byte[] contentBytes, byte[] signatureBytes) throws SignatureVerificationException {
        try {
            if (!(key instanceof PublicKey)) {
                throw new IllegalArgumentException("The given RSAKey is not a RSAPublicKey.");
            }
            boolean valid = crypto.verifySignatureFor(getDescription(), (RSAPublicKey) key, contentBytes, signatureBytes);
            if (!valid) {
                throw new SignatureVerificationException(this);
            }
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new SignatureVerificationException(this, e);
        }
    }

    @Override
    public byte[] sign(byte[] contentBytes) throws SignatureGenerationException {
        try {
            if (!(key instanceof PrivateKey)) {
                throw new IllegalArgumentException("The given RSAKey is not a RSAPrivateKey.");
            }
            return crypto.createSignatureFor(getDescription(), (RSAPrivateKey) key, contentBytes);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | IllegalArgumentException e) {
            throw new SignatureGenerationException(this, e);
        }
    }
}
