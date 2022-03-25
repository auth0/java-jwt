package com.auth0.jwt;

import com.auth0.jwt.impl.PublicClaims;

import static com.auth0.jwt.JWTVerifier.AUDIENCE_CONTAINS;
import static com.auth0.jwt.JWTVerifier.AUDIENCE_EXACT;

public class ClaimFactory {
    public ExpectedClaimType createExpectedClaim(String type) {
        if (type == null || type.isEmpty()) {
            return null;
        }
        switch (type) {
            // We use custom keys for audience in the expected claims to differentiate between validating that the audience
            // contains all expected values, or validating that the audience contains at least one of the expected values.
            case AUDIENCE_EXACT:
                return new AudienceExact();
            case AUDIENCE_CONTAINS:
                return new AudienceContains();
            case PublicClaims.EXPIRES_AT:
                return new PublicClaimsExpiresAt();
            case PublicClaims.ISSUED_AT:
                return new PublicClaimsIssuedAt();
            case PublicClaims.NOT_BEFORE:
                return new PublicClaimsNotBefore();
            case PublicClaims.ISSUER:
                return new PublicClaimsIssuer();
            case PublicClaims.JWT_ID:
                return new PublicClaimsJwtId();
            case PublicClaims.SUBJECT:
                return new PublicClaimsSubject();
            default:
                return new PublicClaimsDefault();
        }
    }
}