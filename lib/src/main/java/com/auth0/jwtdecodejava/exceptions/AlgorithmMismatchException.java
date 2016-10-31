package com.auth0.jwtdecodejava.exceptions;

public class AlgorithmMismatchException extends JWTVerificationException {
    public AlgorithmMismatchException(String message) {
        super(message);
    }
}
