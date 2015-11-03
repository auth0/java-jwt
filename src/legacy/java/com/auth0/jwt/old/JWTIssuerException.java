package com.auth0.jwt.old;

public class JWTIssuerException extends JWTVerifyException {
    private final String issuer;

    public JWTIssuerException(String issuer) {
        this.issuer = issuer;
    }

    public JWTIssuerException(String message, String issuer) {
        super(message);
        this.issuer = issuer;
    }

    public String getIssuer() {
        return issuer;
    }
}
