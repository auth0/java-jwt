package com.auth0.jwt.exceptions;

import com.auth0.jwt.interfaces.Claim;

/**
 * This exception is thrown when the expected value is not found while verifying the Claims.
 */
public class IncorrectClaimException extends InvalidClaimException {
    private final String claimName;

    private final Claim claimValue;

    public IncorrectClaimException(String message, String claimName, Claim claim) {
        super(message);
        this.claimName = claimName;
        this.claimValue = claim;
    }

    public String getClaimName() {
        return claimName;
    }

    public Claim getClaimValue() {
        return claimValue;
    }
}