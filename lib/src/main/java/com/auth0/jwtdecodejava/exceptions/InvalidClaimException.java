package com.auth0.jwtdecodejava.exceptions;


public class InvalidClaimException extends JWTException {
    public InvalidClaimException(String description) {
        super(description);
    }
}
