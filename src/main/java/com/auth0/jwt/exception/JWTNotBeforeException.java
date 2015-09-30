package com.auth0.jwt.exception;

import com.auth0.jwt.JWTVerifyException;

public class JWTNotBeforeException extends JWTVerifyException {
    private long expiration;

    public JWTNotBeforeException(long expiration) {
        this.expiration = expiration;
    }

    public JWTNotBeforeException(String message, long expiration) {
        super(message);
        this.expiration = expiration;
    }

    public long getExpiration() {
        return expiration;
    };
}
