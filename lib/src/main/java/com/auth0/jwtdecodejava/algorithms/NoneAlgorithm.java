package com.auth0.jwtdecodejava.algorithms;

import com.auth0.jwtdecodejava.exceptions.SignatureVerificationException;

class NoneAlgorithm extends Algorithm {

    NoneAlgorithm() {
        super("none", "none");
    }

    @Override
    public void verify(String[] jwtParts) throws SignatureVerificationException {
        if (!jwtParts[2].isEmpty()) {
            throw new SignatureVerificationException(this);
        }
    }
}
