package com.auth0.jwtdecodejava.exceptions;


public class InvalidClaimException extends JWTVerificationException {
    public InvalidClaimException(String message) {
        super(message);
    }
}
