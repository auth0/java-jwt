package com.auth0.jwt.exceptions;

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
