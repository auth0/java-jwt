package com.auth0.jwt.interfaces;

import com.auth0.jwt.JWTVerifier;

import java.time.Instant;

/**
 * Holds the Claims and claim-based configurations required for a JWT to be considered valid.
 */
public interface Verification {
    /**
     * Require a specific Issuer ("iss") claim.
     *
     * @param issuer the required Issuer value. If multiple values are given, the claim must at least match one of them
     * @return this same Verification instance.
     */
    Verification withIssuer(String... issuer);

    /**
     * Require a specific Subject ("sub") claim.
     *
     * @param subject the required Subject value
     * @return this same Verification instance.
     */
    Verification withSubject(String subject);

    /**
     * Require a specific Audience ("aud") claim.
     *
     * @param audience the required Audience value
     * @return this same Verification instance.
     */
    Verification withAudience(String... audience);

    /**
     * Define the default window in seconds in which the Not Before, Issued At and Expires At Claims will still be valid.
     * Setting a specific leeway value on a given Claim will override this value for that Claim.
     *
     * @param leeway the window in seconds in which the Not Before, Issued At and Expires At Claims will still be valid.
     * @return this same Verification instance.
     * @throws IllegalArgumentException if leeway is negative.
     */
    Verification acceptLeeway(long leeway) throws IllegalArgumentException;

    /**
     * Set a specific leeway window in seconds in which the Expires At ("exp") Claim will still be valid.
     * Expiration Date is always verified when the value is present. This method overrides the value set with acceptLeeway
     *
     * @param leeway the window in seconds in which the Expires At Claim will still be valid.
     * @return this same Verification instance.
     * @throws IllegalArgumentException if leeway is negative.
     */
    Verification acceptExpiresAt(long leeway) throws IllegalArgumentException;

    /**
     * Set a specific leeway window in seconds in which the Not Before ("nbf") Claim will still be valid.
     * Not Before Date is always verified when the value is present. This method overrides the value set with acceptLeeway
     *
     * @param leeway the window in seconds in which the Not Before Claim will still be valid.
     * @return this same Verification instance.
     * @throws IllegalArgumentException if leeway is negative.
     */
    Verification acceptNotBefore(long leeway) throws IllegalArgumentException;

    /**
     * Set a specific leeway window in seconds in which the Issued At ("iat") Claim will still be valid.
     * Issued At Date is always verified when the value is present. This method overrides the value set with acceptLeeway
     *
     * @param leeway the window in seconds in which the Issued At Claim will still be valid.
     * @return this same Verification instance.
     * @throws IllegalArgumentException if leeway is negative.
     */
    Verification acceptIssuedAt(long leeway) throws IllegalArgumentException;

    /**
     * Require a specific JWT Id ("jti") claim.
     *
     * @param jwtId the required Id value
     * @return this same Verification instance.
     */
    Verification withJWTId(String jwtId);

    /**
     * Require a specific Claim value.
     *
     * @param name  the Claim's name.
     * @param value the Claim's value.
     * @return this same Verification instance.
     * @throws IllegalArgumentException if the name is null.
     */
    Verification withClaim(String name, Boolean value) throws IllegalArgumentException;

    /**
     * Require a specific Claim value.
     *
     * @param name  the Claim's name.
     * @param value the Claim's value.
     * @return this same Verification instance.
     * @throws IllegalArgumentException if the name is null.
     */
    Verification withClaim(String name, Integer value) throws IllegalArgumentException;

    /**
     * Require a specific Claim value.
     *
     * @param name  the Claim's name.
     * @param value the Claim's value.
     * @return this same Verification instance.
     * @throws IllegalArgumentException if the name is null.
     */
    Verification withClaim(String name, Long value) throws IllegalArgumentException;

    /**
     * Require a specific Claim value.
     *
     * @param name  the Claim's name.
     * @param value the Claim's value.
     * @return this same Verification instance.
     * @throws IllegalArgumentException if the name is null.
     */
    Verification withClaim(String name, Double value) throws IllegalArgumentException;

    /**
     * Require a specific Claim value.
     *
     * @param name  the Claim's name.
     * @param value the Claim's value.
     * @return this same Verification instance.
     * @throws IllegalArgumentException if the name is null.
     */
    Verification withClaim(String name, String value) throws IllegalArgumentException;

    /**
     * Require a specific Claim value.
     *
     * @param name  the Claim's name.
     * @param value the Claim's value.
     * @return this same Verification instance.
     * @throws IllegalArgumentException if the name is null.
     */
    Verification withClaim(String name, Instant value) throws IllegalArgumentException;

    /**
     * Require a specific Array Claim to contain at least the given items.
     *
     * @param name  the Claim's name.
     * @param items the items the Claim must contain.
     * @return this same Verification instance.
     * @throws IllegalArgumentException if the name is null.
     */
    Verification withArrayClaim(String name, String... items) throws IllegalArgumentException;

    /**
     * Require a specific Array Claim to contain at least the given items.
     *
     * @param name  the Claim's name.
     * @param items the items the Claim must contain.
     * @return this same Verification instance.
     * @throws IllegalArgumentException if the name is null.
     */
    Verification withArrayClaim(String name, Integer... items) throws IllegalArgumentException;

    /**
     * Skip the Issued At ("iat") date verification. By default, the verification is performed.
     */
    Verification ignoreIssuedAt();

    /**
     * Creates a new and reusable instance of the JWTVerifier with the configuration already provided.
     *
     * @return a new JWTVerifier instance.
     */
    JWTVerifier build();
}
