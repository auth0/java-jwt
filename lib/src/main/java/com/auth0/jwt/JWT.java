package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;

import java.util.Date;
import java.util.List;

public final class JWT implements com.auth0.jwt.interfaces.JWT {

    private final com.auth0.jwt.interfaces.JWT jwt;

    JWT(com.auth0.jwt.interfaces.JWT jwt) {
        this.jwt = jwt;
    }

    /**
     * Decode a given Token into a JWT instance.
     * Note that this method doesn't verify the JWT's signature! Use it only if you trust the issuer of the Token.
     *
     * @param token the String representation of the JWT.
     * @return a decoded JWT.
     * @throws JWTDecodeException if any part of the Token contained an invalid JWT or JSON format.
     */
    public static JWT decode(String token) throws JWTDecodeException {
        return new JWT(JWTDecoder.decode(token));
    }

    /**
     * Creates a Verification instance to configure and verify a Token using the given Algorithm.
     *
     * @param algorithm the Algorithm to use in JWT verifications.
     * @return a Verification instance to configure.
     * @throws IllegalArgumentException if the provided algorithm is null.
     */
    public static JWTVerifier.Verification require(Algorithm algorithm) throws IllegalArgumentException {
        return JWTVerifier.init(algorithm);
    }

    /**
     * Creates a Builder instance to configure and construct a Token using the given Algorithm.
     *
     * @return a Builder instance to configure.
     */
    public static JWTCreator.Builder create() {
        return JWTCreator.init();
    }

    @Override
    public String getSignature() {
        return jwt.getSignature();
    }

    @Override
    public String getIssuer() {
        return jwt.getIssuer();
    }

    @Override
    public String getSubject() {
        return jwt.getSubject();
    }

    @Override
    public List<String> getAudience() {
        return jwt.getAudience();
    }

    @Override
    public Date getExpiresAt() {
        return jwt.getExpiresAt();
    }

    @Override
    public Date getNotBefore() {
        return jwt.getNotBefore();
    }

    @Override
    public Date getIssuedAt() {
        return jwt.getIssuedAt();
    }

    @Override
    public String getId() {
        return jwt.getId();
    }

    @Override
    public Claim getClaim(String name) {
        return jwt.getClaim(name);
    }

    @Override
    public Claim getHeaderClaim(String name) {
        return jwt.getHeaderClaim(name);
    }

    @Override
    public String getAlgorithm() {
        return jwt.getAlgorithm();
    }

    @Override
    public String getType() {
        return jwt.getType();
    }

    @Override
    public String getContentType() {
        return jwt.getContentType();
    }

    @Override
    public String getKeyId() {
        return jwt.getKeyId();
    }
}
