package com.auth0.jwtdecodejava.exceptions;

public class JWTDecodeException extends RuntimeException {
    public JWTDecodeException(String message) {
        this(message, null);
    }

    public JWTDecodeException(String message, Throwable cause) {
        super(message, cause);
    }
}
