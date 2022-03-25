package com.auth0.jwt.exceptions;

/**
 * The exception that is thrown if the token is expired.
 */
public class TokenExpiredException extends JWTVerificationException {

    private static final long serialVersionUID = -7076928975713577708L;

    public TokenExpiredException(String message) {
        super(message);
    }
}
