package com.auth0.jwt;


/**
 * Represents Exception related to Expiration - for example JWT token has expired
 */
public class JWTExpiredException extends JWTVerifyException {

    private long expiration;

    public JWTExpiredException(final long expiration) {
        this.expiration = expiration;
    }

    public JWTExpiredException(final String message, final long expiration) {
        super(message);
        this.expiration = expiration;
    }

    public long getExpiration() {
        return expiration;
    };
}
