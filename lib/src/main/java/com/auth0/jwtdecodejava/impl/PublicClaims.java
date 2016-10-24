package com.auth0.jwtdecodejava.impl;


public final class PublicClaims {

    private PublicClaims() {
    }

    public static final String ISSUER = "iss";
    public static final String SUBJECT = "sub";
    public static final String EXPIRES_AT = "exp";
    public static final String NOT_BEFORE = "nbf";
    public static final String ISSUED_AT = "iat";
    public static final String JWT_ID = "jti";
    public static final String AUDIENCE = "aud";
}
