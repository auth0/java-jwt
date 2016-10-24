package com.auth0.jwtdecodejava.exceptions;

public class JWTException extends RuntimeException {
    public JWTException(String message) {
        this(message, null);
    }

    public JWTException(String message, Throwable cause) {
        super(message, cause);
    }
}
