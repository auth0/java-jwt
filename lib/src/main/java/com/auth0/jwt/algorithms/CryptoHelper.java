package com.auth0.jwt.algorithms;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

class CryptoHelper {

    boolean verifySignatureFor(String algorithm, byte[] secretBytes, byte[] contentBytes, byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException {
        return MessageDigest.isEqual(createSignatureFor(algorithm, secretBytes, contentBytes), signatureBytes);
    }

    byte[] createSignatureFor(String algorithm, byte[] secretBytes, byte[] contentBytes) throws NoSuchAlgorithmException, InvalidKeyException {
        final Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(secretBytes, algorithm));
        return mac.doFinal(contentBytes);
    }

    boolean verifySignatureFor(String algorithm, PublicKey publicKey, byte[] contentBytes, byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature s = Signature.getInstance(algorithm);
        s.initVerify(publicKey);
        s.update(contentBytes);
        return s.verify(signatureBytes);
    }

    byte[] createSignatureFor(String algorithm, PrivateKey privateKey, byte[] contentBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature s = Signature.getInstance(algorithm);
        s.initSign(privateKey);
        s.update(contentBytes);
        return s.sign();
    }
}
