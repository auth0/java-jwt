package com.auth0.jwtdecodejava.algorithms;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

class CryptoHelper {

    boolean verifyMacFor(String algorithm, byte[] secretBytes, byte[] contentBytes, byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException {
        final Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(secretBytes, algorithm));
        byte[] result = mac.doFinal(contentBytes);
        return MessageDigest.isEqual(result, signatureBytes);
    }

    boolean verifySignatureFor(String algorithm, PublicKey publicKey, byte[] contentBytes, byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature s = Signature.getInstance(algorithm);
        s.initVerify(publicKey);
        s.update(contentBytes);
        return s.verify(signatureBytes);
    }
}
