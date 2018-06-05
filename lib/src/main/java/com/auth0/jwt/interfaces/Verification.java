package com.auth0.jwt.interfaces;

import com.auth0.jwt.JWTVerifier;

import java.util.Date;

public interface Verification {
    Verification withFeature(VerificationFeature... features);

    Verification withIssuer(String... issuer);

    Verification withSubject(String subject);

    Verification withAudience(String... audience);

    Verification acceptLeeway(long leeway) throws IllegalArgumentException;

    Verification acceptExpiresAt(long leeway) throws IllegalArgumentException;

    Verification acceptNotBefore(long leeway) throws IllegalArgumentException;

    Verification acceptIssuedAt(long leeway) throws IllegalArgumentException;

    Verification withJWTId(String jwtId);

    Verification withClaim(String name, Boolean value) throws IllegalArgumentException;

    Verification withClaim(String name, Integer value) throws IllegalArgumentException;

    Verification withClaim(String name, Long value) throws IllegalArgumentException;

    Verification withClaim(String name, Double value) throws IllegalArgumentException;

    Verification withClaim(String name, String value) throws IllegalArgumentException;

    Verification withClaim(String name, Date value) throws IllegalArgumentException;

    Verification withArrayClaim(String name, String... items) throws IllegalArgumentException;

    Verification withArrayClaim(String name, Integer... items) throws IllegalArgumentException;

    Verification ignoreIssuedAt();

    JWTVerifier build();
}
