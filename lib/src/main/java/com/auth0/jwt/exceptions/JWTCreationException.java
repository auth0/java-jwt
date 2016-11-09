package com.auth0.jwt.exceptions;

public class JWTCreationException extends RuntimeException {
    public JWTCreationException(String message) {
        this(message, null);
    }

    public JWTCreationException(String message, Throwable cause) {
        super(message, cause);
    }
}
