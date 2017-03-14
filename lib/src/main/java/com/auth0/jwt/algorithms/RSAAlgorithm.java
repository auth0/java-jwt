package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

class RSAAlgorithm extends Algorithm {

    private final RSAKeyProvider keyProvider;
    private final CryptoHelper crypto;

    //Visible for testing
    RSAAlgorithm(CryptoHelper crypto, String id, String algorithm, RSAKeyProvider keyProvider) throws IllegalArgumentException {
        super(id, algorithm);
        if (keyProvider == null) {
            throw new IllegalArgumentException("The Key Provider cannot be null.");
        }
        if (keyProvider.getPublicKey() == null && keyProvider.getPrivateKey() == null) {
            throw new IllegalArgumentException("Both provided Keys cannot be null.");
        }
        this.keyProvider = keyProvider;
        this.crypto = crypto;
    }

    RSAAlgorithm(String id, String algorithm, RSAKeyProvider keyProvider) throws IllegalArgumentException {
        this(new CryptoHelper(), id, algorithm, keyProvider);
    }

    RSAPublicKey getPublicKey() {
        return keyProvider.getPublicKey();
    }

    RSAPrivateKey getPrivateKey() {
        return keyProvider.getPrivateKey();
    }

    @Override
    public void verify(byte[] contentBytes, byte[] signatureBytes) throws SignatureVerificationException {
        try {
            if (keyProvider.getPublicKey() == null) {
                throw new IllegalStateException("The given Public Key is null.");
            }
            boolean valid = crypto.verifySignatureFor(getDescription(), keyProvider.getPublicKey(), contentBytes, signatureBytes);
            if (!valid) {
                throw new SignatureVerificationException(this);
            }
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | IllegalStateException e) {
            throw new SignatureVerificationException(this, e);
        }
    }

    @Override
    public byte[] sign(byte[] contentBytes) throws SignatureGenerationException {
        try {
            if (keyProvider.getPrivateKey() == null) {
                throw new IllegalStateException("The given Private Key is null.");
            }
            return crypto.createSignatureFor(getDescription(), keyProvider.getPrivateKey(), contentBytes);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | IllegalStateException e) {
            throw new SignatureGenerationException(this, e);
        }
    }

    //Visible for testing
    static RSAKeyProvider providerForKeys(final RSAPublicKey publicKey, final RSAPrivateKey privateKey) {
        return new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKey() {
                return publicKey;
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                return privateKey;
            }
        };
    }
}
