package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Base64;

class NoneAlgorithm extends Algorithm {

    NoneAlgorithm() {
        super("none", "none");
    }

    @Override
    public void verify(DecodedJWT jwt, boolean isUrlEncoded) throws SignatureVerificationException {
        try {
            Base64.Decoder decoder = isUrlEncoded ? Base64.getUrlDecoder() : Base64.getDecoder();

            byte[] signatureBytes = decoder.decode(jwt.getSignature());

            if (signatureBytes.length > 0) {
                throw new SignatureVerificationException(this);
            }
        } catch (IllegalArgumentException e) {
            throw new SignatureVerificationException(this, e);
        }
    }

    @Override
    public byte[] sign(byte[] headerBytes, byte[] payloadBytes) throws SignatureGenerationException {
        return new byte[0];
    }

    @Override
    @Deprecated
    public byte[] sign(byte[] contentBytes) throws SignatureGenerationException {
        return new byte[0];
    }
}
