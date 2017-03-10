package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;

import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.*;

/**
 * The Algorithm class represents an algorithm to be used in the Signing or Verification process of a Token.
 */
@SuppressWarnings("WeakerAccess")
public abstract class Algorithm {

    private final String name;
    private final String description;

    /**
     * Creates a new Algorithm instance using SHA256withRSA. Tokens specify this as "RS256".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid RSA256 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     * @deprecated use {@link #RSA256(RSAPublicKey, RSAPrivateKey)}
     */
    @Deprecated
    public static Algorithm RSA256(RSAKey key) throws IllegalArgumentException {
        RSAPublicKey publicKey = key instanceof PublicKey ? (RSAPublicKey) key : null;
        RSAPrivateKey privateKey = key instanceof PrivateKey ? (RSAPrivateKey) key : null;
        return RSA256(publicKey, privateKey);
    }

    /**
     * Creates a new Algorithm instance using SHA384withRSA. Tokens specify this as "RS384".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid RSA384 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     * @deprecated use {@link #RSA384(RSAPublicKey, RSAPrivateKey)}
     */
    @Deprecated
    public static Algorithm RSA384(RSAKey key) throws IllegalArgumentException {
        RSAPublicKey publicKey = key instanceof PublicKey ? (RSAPublicKey) key : null;
        RSAPrivateKey privateKey = key instanceof PrivateKey ? (RSAPrivateKey) key : null;
        return RSA384(publicKey, privateKey);
    }

    /**
     * Creates a new Algorithm instance using SHA512withRSA. Tokens specify this as "RS512".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid RSA512 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     * @deprecated use {@link #RSA512(RSAPublicKey, RSAPrivateKey)}
     */
    @Deprecated
    public static Algorithm RSA512(RSAKey key) throws IllegalArgumentException {
        RSAPublicKey publicKey = key instanceof PublicKey ? (RSAPublicKey) key : null;
        RSAPrivateKey privateKey = key instanceof PrivateKey ? (RSAPrivateKey) key : null;
        return RSA512(publicKey, privateKey);
    }

    /**
     * Creates a new Algorithm instance using SHA256withRSA. Tokens specify this as "RS256".
     *
     * @param publicKey  the key to use in the verify instance.
     * @param privateKey the key to use in the signing instance.
     * @return a valid RSA256 Algorithm.
     * @throws IllegalArgumentException if both provided Keys are null.
     */
    public static Algorithm RSA256(RSAPublicKey publicKey, RSAPrivateKey privateKey) throws IllegalArgumentException {
        return new RSAAlgorithm("RS256", "SHA256withRSA", publicKey, privateKey);
    }

    /**
     * Creates a new Algorithm instance using SHA384withRSA. Tokens specify this as "RS384".
     *
     * @param publicKey  the key to use in the verify instance.
     * @param privateKey the key to use in the signing instance.
     * @return a valid RSA384 Algorithm.
     * @throws IllegalArgumentException if both provided Keys are null.
     */
    public static Algorithm RSA384(RSAPublicKey publicKey, RSAPrivateKey privateKey) throws IllegalArgumentException {
        return new RSAAlgorithm("RS384", "SHA384withRSA", publicKey, privateKey);
    }

    /**
     * Creates a new Algorithm instance using SHA512withRSA. Tokens specify this as "RS512".
     *
     * @param publicKey  the key to use in the verify instance.
     * @param privateKey the key to use in the signing instance.
     * @return a valid RSA512 Algorithm.
     * @throws IllegalArgumentException if both provided Keys are null.
     */
    public static Algorithm RSA512(RSAPublicKey publicKey, RSAPrivateKey privateKey) throws IllegalArgumentException {
        return new RSAAlgorithm("RS512", "SHA512withRSA", publicKey, privateKey);
    }

    /**
     * Creates a new Algorithm instance using HmacSHA256. Tokens specify this as "HS256".
     *
     * @param secret the secret to use in the verify or signing instance.
     * @return a valid HMAC256 Algorithm.
     * @throws IllegalArgumentException     if the provided Secret is null.
     * @throws UnsupportedEncodingException if the current Java platform implementation doesn't support the UTF-8 character encoding.
     */
    public static Algorithm HMAC256(String secret) throws IllegalArgumentException, UnsupportedEncodingException {
        return new HMACAlgorithm("HS256", "HmacSHA256", secret);
    }

    /**
     * Creates a new Algorithm instance using HmacSHA384. Tokens specify this as "HS384".
     *
     * @param secret the secret to use in the verify or signing instance.
     * @return a valid HMAC384 Algorithm.
     * @throws IllegalArgumentException     if the provided Secret is null.
     * @throws UnsupportedEncodingException if the current Java platform implementation doesn't support the UTF-8 character encoding.
     */
    public static Algorithm HMAC384(String secret) throws IllegalArgumentException, UnsupportedEncodingException {
        return new HMACAlgorithm("HS384", "HmacSHA384", secret);
    }

    /**
     * Creates a new Algorithm instance using HmacSHA512. Tokens specify this as "HS512".
     *
     * @param secret the secret to use in the verify or signing instance.
     * @return a valid HMAC512 Algorithm.
     * @throws IllegalArgumentException     if the provided Secret is null.
     * @throws UnsupportedEncodingException if the current Java platform implementation doesn't support the UTF-8 character encoding.
     */
    public static Algorithm HMAC512(String secret) throws IllegalArgumentException, UnsupportedEncodingException {
        return new HMACAlgorithm("HS512", "HmacSHA512", secret);
    }

    /**
     * Creates a new Algorithm instance using HmacSHA256. Tokens specify this as "HS256".
     *
     * @param secret the secret bytes to use in the verify or signing instance.
     * @return a valid HMAC256 Algorithm.
     * @throws IllegalArgumentException if the provided Secret is null.
     */
    public static Algorithm HMAC256(byte[] secret) throws IllegalArgumentException {
        return new HMACAlgorithm("HS256", "HmacSHA256", secret);
    }

    /**
     * Creates a new Algorithm instance using HmacSHA384. Tokens specify this as "HS384".
     *
     * @param secret the secret bytes to use in the verify or signing instance.
     * @return a valid HMAC384 Algorithm.
     * @throws IllegalArgumentException if the provided Secret is null.
     */
    public static Algorithm HMAC384(byte[] secret) throws IllegalArgumentException {
        return new HMACAlgorithm("HS384", "HmacSHA384", secret);
    }

    /**
     * Creates a new Algorithm instance using HmacSHA512. Tokens specify this as "HS512".
     *
     * @param secret the secret bytes to use in the verify or signing instance.
     * @return a valid HMAC512 Algorithm.
     * @throws IllegalArgumentException if the provided Secret is null.
     */
    public static Algorithm HMAC512(byte[] secret) throws IllegalArgumentException {
        return new HMACAlgorithm("HS512", "HmacSHA512", secret);
    }

    /**
     * Creates a new Algorithm instance using SHA256withECDSA. Tokens specify this as "ES256".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid ECDSA256 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     * @deprecated use {@link #ECDSA256(ECPublicKey, ECPrivateKey)}
     */
    @Deprecated
    public static Algorithm ECDSA256(ECKey key) throws IllegalArgumentException {
        ECPublicKey publicKey = key instanceof PublicKey ? (ECPublicKey) key : null;
        ECPrivateKey privateKey = key instanceof PrivateKey ? (ECPrivateKey) key : null;
        return ECDSA256(publicKey, privateKey);
    }

    /**
     * Creates a new Algorithm instance using SHA384withECDSA. Tokens specify this as "ES384".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid ECDSA384 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     * @deprecated use {@link #ECDSA384(ECPublicKey, ECPrivateKey)}
     */
    @Deprecated
    public static Algorithm ECDSA384(ECKey key) throws IllegalArgumentException {
        ECPublicKey publicKey = key instanceof PublicKey ? (ECPublicKey) key : null;
        ECPrivateKey privateKey = key instanceof PrivateKey ? (ECPrivateKey) key : null;
        return ECDSA384(publicKey, privateKey);
    }

    /**
     * Creates a new Algorithm instance using SHA512withECDSA. Tokens specify this as "ES512".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid ECDSA512 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     * @deprecated use {@link #ECDSA512(ECPublicKey, ECPrivateKey)}
     */
    @Deprecated
    public static Algorithm ECDSA512(ECKey key) throws IllegalArgumentException {
        ECPublicKey publicKey = key instanceof PublicKey ? (ECPublicKey) key : null;
        ECPrivateKey privateKey = key instanceof PrivateKey ? (ECPrivateKey) key : null;
        return ECDSA512(publicKey, privateKey);
    }

    /**
     * Creates a new Algorithm instance using SHA256withECDSA. Tokens specify this as "ES256".
     *
     * @param publicKey  the key to use in the verify instance.
     * @param privateKey the key to use in the signing instance.
     * @return a valid ECDSA256 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     */
    public static Algorithm ECDSA256(ECPublicKey publicKey, ECPrivateKey privateKey) throws IllegalArgumentException {
        return new ECDSAAlgorithm("ES256", "SHA256withECDSA", 32, publicKey, privateKey);
    }

    /**
     * Creates a new Algorithm instance using SHA384withECDSA. Tokens specify this as "ES384".
     *
     * @param publicKey  the key to use in the verify instance.
     * @param privateKey the key to use in the signing instance.
     * @return a valid ECDSA384 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     */
    public static Algorithm ECDSA384(ECPublicKey publicKey, ECPrivateKey privateKey) throws IllegalArgumentException {
        return new ECDSAAlgorithm("ES384", "SHA384withECDSA", 48, publicKey, privateKey);
    }

    /**
     * Creates a new Algorithm instance using SHA512withECDSA. Tokens specify this as "ES512".
     *
     * @param publicKey  the key to use in the verify instance.
     * @param privateKey the key to use in the signing instance.
     * @return a valid ECDSA512 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     */
    public static Algorithm ECDSA512(ECPublicKey publicKey, ECPrivateKey privateKey) throws IllegalArgumentException {
        return new ECDSAAlgorithm("ES512", "SHA512withECDSA", 66, publicKey, privateKey);
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
     * Verify the given content using this Algorithm instance.
     *
     * @param contentBytes   an array of bytes representing the base64 encoded content to be verified against the signature.
     * @param signatureBytes an array of bytes representing the base64 encoded signature to compare the content against.
     * @throws SignatureVerificationException if the Token's Signature is invalid, meaning that it doesn't match the signatureBytes, or if the Key is invalid.
     */
    public abstract void verify(byte[] contentBytes, byte[] signatureBytes) throws SignatureVerificationException;

    /**
     * Sign the given content using this Algorithm instance.
     *
     * @param contentBytes an array of bytes representing the base64 encoded content to be verified against the signature.
     * @return the signature in a base64 encoded array of bytes
     * @throws SignatureGenerationException if the Key is invalid.
     */
    public abstract byte[] sign(byte[] contentBytes) throws SignatureGenerationException;
}
