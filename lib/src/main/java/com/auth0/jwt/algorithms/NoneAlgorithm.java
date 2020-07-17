package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.codec.binary.Base64;
import org.jetbrains.annotations.NotNull;

class NoneAlgorithm extends Algorithm {

    NoneAlgorithm() {
        super("none", "none");
    }

    @Override
    public void verify(@NotNull DecodedJWT jwt) throws SignatureVerificationException {
        byte[] signatureBytes = Base64.decodeBase64(jwt.getSignature());
        if (signatureBytes.length > 0) {
            throw new SignatureVerificationException(this);
        }
    }

    @NotNull
    @Override
    public byte[] sign(@NotNull byte[] headerBytes, @NotNull byte[] payloadBytes) throws SignatureGenerationException {
        return new byte[0];
    }

    @NotNull
    @Override
    @Deprecated
    public byte[] sign(@NotNull byte[] contentBytes) throws SignatureGenerationException {
        return new byte[0];
    }
}
