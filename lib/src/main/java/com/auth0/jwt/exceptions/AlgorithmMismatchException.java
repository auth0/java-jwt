package com.auth0.jwt.exceptions;

public class AlgorithmMismatchException extends JWTVerificationException {
    public AlgorithmMismatchException(String message) {
        super(message);
    }
}
