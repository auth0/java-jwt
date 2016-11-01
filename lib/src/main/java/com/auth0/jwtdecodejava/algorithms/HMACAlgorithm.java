package com.auth0.jwtdecodejava.algorithms;

import com.auth0.jwtdecodejava.exceptions.SignatureVerificationException;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class HMACAlgorithm extends Algorithm {

    private final String secret;

    HMACAlgorithm(String id, String algorithm, String secret) {
        super(id, algorithm);
        if (secret == null) {
            throw new IllegalArgumentException("The Secret cannot be null");
        }
        this.secret = secret;
    }

    String getSecret() {
        return secret;
    }

    @Override
    public void verify(String[] jwtParts) throws SignatureVerificationException {
        try {
            Mac mac = Mac.getInstance(getDescription());
            mac.init(new SecretKeySpec(secret.getBytes(), getDescription()));
            String message = String.format("%s.%s", jwtParts[0], jwtParts[1]);
            byte[] result = mac.doFinal(message.getBytes());
            boolean valid = MessageDigest.isEqual(result, Base64.decodeBase64(jwtParts[2]));
            if (!valid) {
                throw new SignatureVerificationException(this);
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new SignatureVerificationException(this, e);
        }
    }
}
