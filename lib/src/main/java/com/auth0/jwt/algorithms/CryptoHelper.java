package com.auth0.jwt.algorithms;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.Charsets;

import java.security.*;

class CryptoHelper {
	
	private static final byte DOT = (byte)46;

    boolean verifySignatureFor(String algorithm, byte[] secretBytes, String header, String payload, byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException {
    	return verifySignatureFor(algorithm, secretBytes, header.getBytes(Charsets.UTF_8), payload.getBytes(Charsets.UTF_8), signatureBytes);
    }

    boolean verifySignatureFor(String algorithm, byte[] secretBytes, byte[] headerBytes, byte[] payloadBytes, byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException {
        return MessageDigest.isEqual(createSignatureFor(algorithm, secretBytes, headerBytes, payloadBytes), signatureBytes);
    }
    
    byte[] createSignatureFor(String algorithm, byte[] secretBytes, byte[] headerBytes, byte[] payloadBytes) throws NoSuchAlgorithmException, InvalidKeyException {
        final Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(secretBytes, algorithm));
        mac.update(headerBytes);
        mac.update(DOT);
        return mac.doFinal(payloadBytes);
    }

    boolean verifySignatureFor(String algorithm, PublicKey publicKey, String header, String payload, byte[] signatureBytes)  throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    	return verifySignatureFor(algorithm, publicKey, header.getBytes(Charsets.UTF_8), payload.getBytes(Charsets.UTF_8), signatureBytes);
    }

    boolean verifySignatureFor(String algorithm, PublicKey publicKey, byte[] headerBytes, byte[] payloadBytes, byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature s = Signature.getInstance(algorithm);
        s.initVerify(publicKey);
        s.update(headerBytes);
        s.update(DOT);
        s.update(payloadBytes);
        return s.verify(signatureBytes);
    }
    
    byte[] createSignatureFor(String algorithm, PrivateKey privateKey, byte[] headerBytes, byte[] payloadBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature s = Signature.getInstance(algorithm);
        s.initSign(privateKey);
        s.update(headerBytes);
        s.update(DOT);
        s.update(payloadBytes);
        return s.sign();
    }
    
    @Deprecated
    boolean verifySignatureFor(String algorithm, byte[] secretBytes, byte[] contentBytes, byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException {
        return MessageDigest.isEqual(createSignatureFor(algorithm, secretBytes, contentBytes), signatureBytes);
    }

    @Deprecated
    byte[] createSignatureFor(String algorithm, byte[] secretBytes, byte[] contentBytes) throws NoSuchAlgorithmException, InvalidKeyException {
        final Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(secretBytes, algorithm));
        return mac.doFinal(contentBytes);
    }

    @Deprecated
    boolean verifySignatureFor(String algorithm, PublicKey publicKey, byte[] contentBytes, byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature s = Signature.getInstance(algorithm);
        s.initVerify(publicKey);
        s.update(contentBytes);
        return s.verify(signatureBytes);
    }

    @Deprecated
    byte[] createSignatureFor(String algorithm, PrivateKey privateKey, byte[] contentBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature s = Signature.getInstance(algorithm);
        s.initSign(privateKey);
        s.update(contentBytes);
        return s.sign();
    }    
}
