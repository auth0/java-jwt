package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import org.apache.commons.codec.binary.Base64;

import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

class RSAAlgorithm extends Algorithm {

    private final RSAKey key;
    private CryptoHelper crypto;

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
    public void verify(String[] jwtParts) throws SignatureVerificationException {
        if (!(key instanceof PublicKey)) {
            throw new IllegalArgumentException("The given RSAKey is not a RSAPublicKey.");
        }
        try {
            String content = String.format("%s.%s", jwtParts[0], jwtParts[1]);
            byte[] signature = Base64.decodeBase64(jwtParts[2]);
            boolean valid = crypto.verifySignatureFor(getDescription(), (RSAPublicKey) key, content.getBytes(), signature);

            if (!valid) {
                throw new SignatureVerificationException(this);
            }
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new SignatureVerificationException(this, e);
        }
    }

    @Override
    public byte[] sign(byte[] headerAndPayloadBytes) throws SignatureGenerationException {
        try {
            if (!(key instanceof PrivateKey)) {
                throw new IllegalArgumentException("The given RSAKey is not a RSAPrivateKey.");
            }
            return crypto.createSignatureFor(getDescription(), (RSAPrivateKey) key, headerAndPayloadBytes);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | IllegalArgumentException e) {
            throw new SignatureGenerationException(this, e);
        }
    }
}
