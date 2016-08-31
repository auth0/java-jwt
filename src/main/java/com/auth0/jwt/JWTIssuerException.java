package com.auth0.jwt;

/**
 * Represents Exception related to Issuer - for example issuer mismatch / missing upon verification
 */
public class JWTIssuerException extends JWTVerifyException {

    private final String issuer;

    public JWTIssuerException(final String issuer) {
        this.issuer = issuer;
    }

    public JWTIssuerException(final String message, final String issuer) {
        super(message);
        this.issuer = issuer;
    }

    public String getIssuer() {
        return issuer;
    }
}
