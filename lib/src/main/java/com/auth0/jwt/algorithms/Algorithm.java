package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;

import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

/**
 * The Algorithm class represents an algorithm to be used in the Signing or Verification process of a Token.
 */
public abstract class Algorithm {

    private final String name;
    private final String description;

    /**
     * Creates a new Algorithm instance using SHA256withRSA. Tokens specify this as "RS256".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid RSA256 Algorithm.
     */
    public static Algorithm RSA256(RSAKey key) {
        return new RSAAlgorithm("RS256", "SHA256withRSA", key);
    }

    /**
     * Creates a new Algorithm instance using SHA384withRSA. Tokens specify this as "RS384".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid RSA384 Algorithm.
     */
    public static Algorithm RSA384(RSAKey key) {
        return new RSAAlgorithm("RS384", "SHA384withRSA", key);
    }

    /**
     * Creates a new Algorithm instance using SHA512withRSA. Tokens specify this as "RS512".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid RSA512 Algorithm.
     */
    public static Algorithm RSA512(RSAKey key) {
        return new RSAAlgorithm("RS512", "SHA512withRSA", key);
    }

    /**
     * Creates a new Algorithm instance using HmacSHA256. Tokens specify this as "HS256".
     *
     * @param secret the secret to use in the verify or signing instance.
     * @return a valid HMAC256 Algorithm.
     */
    public static Algorithm HMAC256(String secret) {
        return new HMACAlgorithm("HS256", "HmacSHA256", secret);
    }

    /**
     * Creates a new Algorithm instance using HmacSHA384. Tokens specify this as "HS384".
     *
     * @param secret the secret to use in the verify or signing instance.
     * @return a valid HMAC384 Algorithm.
     */
    public static Algorithm HMAC384(String secret) {
        return new HMACAlgorithm("HS384", "HmacSHA384", secret);
    }

    /**
     * Creates a new Algorithm instance using HmacSHA512. Tokens specify this as "HS512".
     *
     * @param secret the secret to use in the verify or signing instance.
     * @return a valid HMAC512 Algorithm.
     */
    public static Algorithm HMAC512(String secret) {
        return new HMACAlgorithm("HS512", "HmacSHA512", secret);
    }

    /**
     * Creates a new Algorithm instance using SHA256withECDSA. Tokens specify this as "ES256".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid ECDSA256 Algorithm.
     */
    public static Algorithm ECDSA256(ECKey key) {
        return new ECDSAAlgorithm("ES256", "SHA256withECDSA", 32, key);
    }

    /**
     * Creates a new Algorithm instance using SHA384withECDSA. Tokens specify this as "ES384".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid ECDSA384 Algorithm.
     */
    public static Algorithm ECDSA384(ECKey key) {
        return new ECDSAAlgorithm("ES384", "SHA384withECDSA", 48, key);
    }

    /**
     * Creates a new Algorithm instance using SHA512withECDSA. Tokens specify this as "ES512".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid ECDSA512 Algorithm.
     */
    public static Algorithm ECDSA512(ECKey key) {
        return new ECDSAAlgorithm("ES512", "SHA512withECDSA", 66, key);
    }

    public static Algorithm none() {
        return new NoneAlgorithm();
    }

    protected Algorithm(String name, String description) {
        this.name = name;
        this.description = description;
    }

    /**
     * Getter for the name of this Algorithm, as defined in the JWT Standard. i.e. "HS256"
     *
     * @return the algorithm name.
     */
    public String getName() {
        return name;
    }

    /**
     * Getter for the description of this Algorithm, required when instantiating a Mac or Signature object. i.e. "HmacSHA256"
     *
     * @return the algorithm description.
     */
    String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return description;
    }

    /**
     * Verify the given JWT parts using this Algorithm instance.
     *
     * @param jwtParts a valid array of size 3 representing the JWT parts.
     * @throws SignatureVerificationException if the Token's Signature is invalid.
     */
    public abstract void verify(String[] jwtParts) throws SignatureVerificationException;

    public abstract byte[] sign(byte[] headerAndPayloadBytes) throws SignatureGenerationException;
}
