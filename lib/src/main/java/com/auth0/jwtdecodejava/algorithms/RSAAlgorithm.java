package com.auth0.jwtdecodejava.algorithms;

import com.auth0.jwtdecodejava.exceptions.SignatureVerificationException;
import org.apache.commons.codec.binary.Base64;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;

class RSAAlgorithm extends Algorithm {

    private final PublicKey publicKey;
    private CryptoHelper crypto;

    RSAAlgorithm(CryptoHelper crypto, String id, String algorithm, PublicKey publicKey) {
        super(id, algorithm);
        if (publicKey == null) {
            throw new IllegalArgumentException("The PublicKey cannot be null");
        }
        this.publicKey = publicKey;
        this.crypto = crypto;
    }

    RSAAlgorithm(String id, String algorithm, PublicKey publicKey) {
        this(new CryptoHelper(), id, algorithm, publicKey);
    }

    PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public void verify(String[] jwtParts) throws SignatureVerificationException {
        try {
            String content = String.format("%s.%s", jwtParts[0], jwtParts[1]);
            byte[] signature = Base64.decodeBase64(jwtParts[2]);
            boolean valid = crypto.verifySignatureFor(getDescription(), publicKey, content.getBytes(), signature);

            if (!valid) {
                throw new SignatureVerificationException(this);
            }
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new SignatureVerificationException(this, e);
        }
    }
}
