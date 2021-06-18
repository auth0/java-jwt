package com.auth0.jwt.exceptions;


public class InvalidClaimException extends JWTVerificationException {
    private final String claimName;

    public InvalidClaimException(String message) {
        super(message);
        this.claimName = null;
    }

    public InvalidClaimException(String message, String claimName) {
        super(message);
        this.claimName = claimName;
    }

    public String getClaimName() {
        return claimName;
    }
}
