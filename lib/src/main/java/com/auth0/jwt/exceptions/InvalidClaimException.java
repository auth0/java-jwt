package com.auth0.jwt.exceptions;

public class InvalidClaimException extends JWTVerificationException {

    public InvalidClaimException(String message) {
        super(message);
    }
}
