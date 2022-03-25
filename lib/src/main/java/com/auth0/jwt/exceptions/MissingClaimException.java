package com.auth0.jwt.exceptions;

/**
 * This exception is thrown when the claim to be verified is missing
 */
public class MissingClaimException extends InvalidClaimException {

    private final String claimName;

    public MissingClaimException(String claimName) {
        super(String.format("The Claim '%s' is not present in the JWT.", claimName));
        this.claimName = claimName;
    }

    public String getClaimName() {
        return claimName;
    }
}
