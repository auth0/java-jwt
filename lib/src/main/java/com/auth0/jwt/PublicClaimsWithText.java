package com.auth0.jwt;

import com.auth0.jwt.exceptions.InvalidClaimException;

public abstract class PublicClaimsWithText implements ExpectedClaimType {
    protected void assertValidStringClaim(String claimName, String value, String expectedValue) {
        if (!expectedValue.equals(value)) {
            throw new InvalidClaimException(String.format("The Claim '%s' value doesn't match the required one.", claimName));
        }
    }
}
