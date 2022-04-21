package com.auth0.jwt.interfaces;

import com.auth0.jwt.exceptions.JWTVerificationException;


/**
 * Used to verify the JWT for its signature and claims.
 */
public interface JWTVerifier {

    /**
     * Performs the verification against the given Token.
     *
     * @param token to verify.
     * @return a verified and decoded JWT.
     * @throws JWTVerificationException if any of the verification steps fail
     */
    DecodedJWT verify(String token) throws JWTVerificationException;

    /**
     * Performs the verification against the given {@link DecodedJWT}.
     *
     * @param jwt to verify.
     * @return a verified and decoded JWT.
     * @throws JWTVerificationException if any of the verification steps fail
     */
    DecodedJWT verify(DecodedJWT jwt) throws JWTVerificationException;
}
