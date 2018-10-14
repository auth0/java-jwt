package com.auth0.jwt.interfaces;

import com.auth0.jwt.exceptions.JWTVerificationException;

/**
 * A custom verification that can be added to the Verifier via
 * {@link Verification#withCustomValidation(CustomValidation)}.
 *
 * The implementation is passed a decoded JWT and should throw JWTVerificationException if the custom
 * verification logic fails.
 */
public interface CustomValidation {
    void validate(DecodedJWT jwt) throws JWTVerificationException;
}
