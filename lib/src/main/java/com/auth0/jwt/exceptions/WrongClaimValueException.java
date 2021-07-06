package com.auth0.jwt.exceptions;

import com.auth0.jwt.interfaces.Claim;

public class WrongClaimValueException extends InvalidClaimException {
    private final String claimName;

    private final Object claimValue;

    public WrongClaimValueException(String message, String claimName, Object claimValue) {
        super(message);
        this.claimName = claimName;
        this.claimValue = claimValue;
    }

    public WrongClaimValueException(String message, String claimName, Claim claim) {
        super(message);
        this.claimName = claimName;
        this.claimValue = claim.toString();
    }

    public String getClaimName() {
        return claimName;
    }

    public Object getClaimValue() {
        return claimValue;
    }
}
