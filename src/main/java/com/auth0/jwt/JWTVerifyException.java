package com.auth0.jwt;

public class JWTVerifyException extends Exception {
    public JWTVerifyException() {
    }

    public JWTVerifyException(String message) {
        super(message);
    }
}
