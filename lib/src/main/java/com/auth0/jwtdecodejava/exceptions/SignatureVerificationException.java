package com.auth0.jwtdecodejava.exceptions;

import com.auth0.jwtdecodejava.enums.Algorithm;

public class SignatureVerificationException extends JWTException {
    public SignatureVerificationException(Algorithm algorithm) {
        this(algorithm, null);
    }

    public SignatureVerificationException(Algorithm algorithm, Throwable cause) {
        super("The Token's Signature resulted invalid when verified using the Algorithm: " + algorithm.name(), cause);
    }
}
