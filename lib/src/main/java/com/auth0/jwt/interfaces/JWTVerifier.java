package com.auth0.jwt.interfaces;

import com.auth0.jwt.exceptions.JWTVerificationException;
import org.jetbrains.annotations.NotNull;


public interface JWTVerifier {

    /**
     * Performs the verification against the given Token
     *
     * @param token to verify.
     * @return a verified and decoded JWT.
     * @throws JWTVerificationException if any of the verification steps fail
     */
    @NotNull
    DecodedJWT verify(String token) throws JWTVerificationException;

    /**
     * Performs the verification against the given decoded JWT
     *
     * @param jwt to verify.
     * @return a verified and decoded JWT.
     * @throws JWTVerificationException if any of the verification steps fail
     */
    @NotNull
    DecodedJWT verify(DecodedJWT jwt) throws JWTVerificationException;
}
