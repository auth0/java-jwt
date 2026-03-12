package com.auth0.jwt.exceptions;

import com.auth0.jwt.RegisteredClaims;
import com.auth0.jwt.interfaces.Claim;

import java.time.Instant;

/**
 * The exception that is thrown if the token is expired.
 */
public class TokenExpiredException extends IncorrectClaimException {

    private static final long serialVersionUID = -7076928975713577708L;

    private final Instant expiredOn;

    public TokenExpiredException(String message, Claim claim) {
        super(message, RegisteredClaims.EXPIRES_AT, claim);
        this.expiredOn = claim.asInstant();
    }

    public Instant getExpiredOn() {
        return expiredOn;
    }
}
