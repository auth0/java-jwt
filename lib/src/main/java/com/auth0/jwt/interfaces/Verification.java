package com.auth0.jwt.interfaces;

import com.auth0.jwt.JWTVerifier;

public interface Verification {
    Verification withIssuer(String issuer);

    Verification withSubject(String subject);

    Verification withAudience(String... audience);

    Verification acceptLeeway(long leeway) throws IllegalArgumentException;

    Verification acceptExpiresAt(long leeway) throws IllegalArgumentException;

    Verification acceptNotBefore(long leeway) throws IllegalArgumentException;

    Verification acceptIssuedAt(long leeway) throws IllegalArgumentException;

    Verification withJWTId(String jwtId);

    <T> Verification withClaim(String name, T value) throws IllegalArgumentException;
    
    <T> Verification withArrayClaim(String name, @SuppressWarnings("unchecked") T... values) throws IllegalArgumentException;

    JWTVerifier build();
}
