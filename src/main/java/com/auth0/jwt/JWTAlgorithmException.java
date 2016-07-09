package com.auth0.jwt;

/**
 * Represents Exception related to Algorithm - for example JWT header algorithm is unsupported / missing
 */
public class JWTAlgorithmException extends JWTVerifyException {


    public JWTAlgorithmException() {}

    public JWTAlgorithmException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public JWTAlgorithmException(final String message) {
        super(message);
    }

}

