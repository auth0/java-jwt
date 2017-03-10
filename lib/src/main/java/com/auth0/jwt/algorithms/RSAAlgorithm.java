package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

class RSAAlgorithm extends Algorithm {

    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;
    private final CryptoHelper crypto;

    //Visible for testing
    RSAAlgorithm(CryptoHelper crypto, String id, String algorithm, RSAPublicKey publicKey, RSAPrivateKey privateKey) throws IllegalArgumentException {
        super(id, algorithm);
        if (publicKey == null && privateKey == null) {
            throw new IllegalArgumentException("Both provided Keys cannot be null.");
        }
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.crypto = crypto;
    }

    RSAAlgorithm(String id, String algorithm, RSAPublicKey publicKey, RSAPrivateKey privateKey) throws IllegalArgumentException {
        this(new CryptoHelper(), id, algorithm, publicKey, privateKey);
    }

    RSAPublicKey getPublicKey() {
        return publicKey;
    }

    RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public void verify(byte[] contentBytes, byte[] signatureBytes) throws SignatureVerificationException {
        try {
            if (publicKey == null) {
                throw new IllegalArgumentException("The given Public Key is null.");
            }
            boolean valid = crypto.verifySignatureFor(getDescription(), publicKey, contentBytes, signatureBytes);
            if (!valid) {
                throw new SignatureVerificationException(this);
            }
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | IllegalArgumentException e) {
            throw new SignatureVerificationException(this, e);
        }
    }

    @Override
    public byte[] sign(byte[] contentBytes) throws SignatureGenerationException {
        try {
            if (privateKey == null) {
                throw new IllegalArgumentException("The given Private Key is null.");
            }
            return crypto.createSignatureFor(getDescription(), privateKey, contentBytes);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | IllegalArgumentException e) {
            throw new SignatureGenerationException(this, e);
        }
    }
}
