package com.auth0.jwt;

import com.auth0.jwt.exceptions.InvalidClaimException;

import java.util.Collections;
import java.util.List;

public abstract class ClaimsWithAudience implements ExpectedClaimType {
    protected void assertValidAudienceClaim(List<String> audience, List<String> values, boolean shouldContainAll) {
        if (audience == null || (shouldContainAll && !audience.containsAll(values)) ||
                (!shouldContainAll && Collections.disjoint(audience, values))) {
            throw new InvalidClaimException("The Claim 'aud' value doesn't contain the required audience.");
        }
    }
}
