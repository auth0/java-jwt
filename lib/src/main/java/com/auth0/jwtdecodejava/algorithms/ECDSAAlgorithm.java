package com.auth0.jwtdecodejava.algorithms;

import com.auth0.jwtdecodejava.exceptions.SignatureVerificationException;
import org.apache.commons.codec.binary.Base64;

import java.security.*;

class ECDSAAlgorithm extends Algorithm {

    private final int ecNumberSize;
    private final PublicKey publicKey;

    ECDSAAlgorithm(String id, String algorithm, int ecNumberSize, PublicKey publicKey) {
        super(id, algorithm);
        if (publicKey == null) {
            throw new IllegalArgumentException("The PublicKey cannot be null");
        }
        this.ecNumberSize = ecNumberSize;
        this.publicKey = publicKey;
    }

    PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public void verify(String[] jwtParts) throws SignatureVerificationException {
        try {
            String content = String.format("%s.%s", jwtParts[0], jwtParts[1]);
            Signature s = Signature.getInstance(getDescription());
            s.initVerify(publicKey);
            s.update(content.getBytes());
            byte[] signature = Base64.decodeBase64(jwtParts[2]);
            if (isJOSESignature(signature)) {
                signature = JOSEToDER(signature);
            }
            boolean valid = s.verify(signature);
            if (!valid) {
                throw new SignatureVerificationException(this);
            }
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new SignatureVerificationException(this, e);
        }
    }

    private boolean isJOSESignature(byte[] signature) {
        //TODO: Check if the signature has JOSE format.
        return true;
    }

    private byte[] JOSEToDER(byte[] joseSignature) throws SignatureException {
        if (joseSignature.length != ecNumberSize * 2) {
            throw new SignatureException(String.format("The signature length was invalid. Expected %d bytes but received %d", ecNumberSize * 2, joseSignature.length));
        }

        // Retrieve R and S number's length and padding.
        int rPadding = countPadding(joseSignature, 0, ecNumberSize);
        int sPadding = countPadding(joseSignature, ecNumberSize, joseSignature.length);
        int rLength = ecNumberSize - rPadding;
        int sLength = ecNumberSize - sPadding;

        int length = 2 + rLength + 2 + sLength;
        if (length > 0xFF) {
            throw new SignatureException("Invalid ECDSA signature format");
        }

        byte[] derSignature;
        int offset;
        if (length > 0x7f) {
            derSignature = new byte[3 + length];
            derSignature[1] = (byte) 0x81;
            offset = 2;
        } else {
            derSignature = new byte[2 + length];
            offset = 1;
        }

        // DER Structure: http://crypto.stackexchange.com/a/1797
        // Header with length info
        derSignature[0] = (byte) 0x30;
        derSignature[offset++] = (byte) length;
        derSignature[offset++] = (byte) 0x02;
        derSignature[offset++] = (byte) rLength;

        // R number
        System.arraycopy(joseSignature, 0, derSignature, offset + (rLength - ecNumberSize), ecNumberSize);
        offset += rLength;

        // S number length
        derSignature[offset++] = (byte) 0x02;
        derSignature[offset++] = (byte) sLength;

        // S number
        System.arraycopy(joseSignature, ecNumberSize, derSignature, offset + (sLength - ecNumberSize), ecNumberSize);

        return derSignature;
    }

    private int countPadding(byte[] bytes, int fromIndex, int toIndex) {
        int padding = 0;
        while (fromIndex + padding < toIndex && bytes[fromIndex + padding] == 0) {
            padding++;
        }
        return bytes[fromIndex + padding] > 0x7f ? padding : padding - 1;
    }
}
