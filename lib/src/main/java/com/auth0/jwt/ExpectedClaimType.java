package com.auth0.jwt;

import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.Clock;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.*;

public interface ExpectedClaimType {
    void assertExpectedClaimType(DecodedJWT jwt, Map.Entry<String, Object> entry, Clock clock);
}

class AudienceExact implements ExpectedClaimType {
    private void assertValidAudienceClaim(List<String> audience, List<String> values, boolean shouldContainAll) {
        if (audience == null || (shouldContainAll && !audience.containsAll(values)) ||
                (!shouldContainAll && Collections.disjoint(audience, values))) {
            throw new InvalidClaimException("The Claim 'aud' value doesn't contain the required audience.");
        }
    }

    @Override
    public void assertExpectedClaimType(DecodedJWT jwt, Map.Entry<String, Object> entry, Clock clock) {
        assertValidAudienceClaim(jwt.getAudience(), (List<String>) entry.getValue(), true);
    }
}

class AudienceContains implements ExpectedClaimType {
    private void assertValidAudienceClaim(List<String> audience, List<String> values, boolean shouldContainAll) {
        if (audience == null || (shouldContainAll && !audience.containsAll(values)) ||
                (!shouldContainAll && Collections.disjoint(audience, values))) {
            throw new InvalidClaimException("The Claim 'aud' value doesn't contain the required audience.");
        }
    }

    @Override
    public void assertExpectedClaimType(DecodedJWT jwt, Map.Entry<String, Object> entry, Clock clock) {
        assertValidAudienceClaim(jwt.getAudience(), (List<String>) entry.getValue(), false);
    }
}

class PublicClaimsExpiresAt implements ExpectedClaimType {
    private void assertValidDateClaim(Date date, long leeway, boolean shouldBeFuture, Clock clock) {
        Date today = new Date(clock.getToday().getTime());
        today.setTime(today.getTime() / 1000 * 1000); // truncate millis
        if (shouldBeFuture) {
            assertDateIsFuture(date, leeway, today);
        } else {
            assertDateIsPast(date, leeway, today);
        }
    }

    private void assertDateIsFuture(Date date, long leeway, Date today) {
        today.setTime(today.getTime() - leeway * 1000);
        if (date != null && today.after(date)) {
            throw new TokenExpiredException(String.format("The Token has expired on %s.", date));
        }
    }

    private void assertDateIsPast(Date date, long leeway, Date today) {
        today.setTime(today.getTime() + leeway * 1000);
        if (date != null && today.before(date)) {
            throw new InvalidClaimException(String.format("The Token can't be used before %s.", date));
        }
    }

    @Override
    public void assertExpectedClaimType(DecodedJWT jwt, Map.Entry<String, Object> entry, Clock clock) {
        assertValidDateClaim(jwt.getExpiresAt(), (Long) entry.getValue(), true, clock);
    }
}

class PublicClaimsIssuedAt implements ExpectedClaimType {
    private void assertValidDateClaim(Date date, long leeway, boolean shouldBeFuture, Clock clock) {
        Date today = new Date(clock.getToday().getTime());
        today.setTime(today.getTime() / 1000 * 1000); // truncate millis
        if (shouldBeFuture) {
            assertDateIsFuture(date, leeway, today);
        } else {
            assertDateIsPast(date, leeway, today);
        }
    }

    private void assertDateIsFuture(Date date, long leeway, Date today) {
        today.setTime(today.getTime() - leeway * 1000);
        if (date != null && today.after(date)) {
            throw new TokenExpiredException(String.format("The Token has expired on %s.", date));
        }
    }

    private void assertDateIsPast(Date date, long leeway, Date today) {
        today.setTime(today.getTime() + leeway * 1000);
        if (date != null && today.before(date)) {
            throw new InvalidClaimException(String.format("The Token can't be used before %s.", date));
        }
    }
    @Override
    public void assertExpectedClaimType(DecodedJWT jwt, Map.Entry<String, Object> entry, Clock clock) {
        assertValidDateClaim(jwt.getIssuedAt(), (Long) entry.getValue(), false, clock);
    }
}

class PublicClaimsNotBefore implements ExpectedClaimType {
    private void assertValidDateClaim(Date date, long leeway, boolean shouldBeFuture, Clock clock) {
        Date today = new Date(clock.getToday().getTime());
        today.setTime(today.getTime() / 1000 * 1000); // truncate millis
        if (shouldBeFuture) {
            assertDateIsFuture(date, leeway, today);
        } else {
            assertDateIsPast(date, leeway, today);
        }
    }

    private void assertDateIsFuture(Date date, long leeway, Date today) {
        today.setTime(today.getTime() - leeway * 1000);
        if (date != null && today.after(date)) {
            throw new TokenExpiredException(String.format("The Token has expired on %s.", date));
        }
    }

    private void assertDateIsPast(Date date, long leeway, Date today) {
        today.setTime(today.getTime() + leeway * 1000);
        if (date != null && today.before(date)) {
            throw new InvalidClaimException(String.format("The Token can't be used before %s.", date));
        }
    }
    @Override
    public void assertExpectedClaimType(DecodedJWT jwt, Map.Entry<String, Object> entry, Clock clock) {
        assertValidDateClaim(jwt.getNotBefore(), (Long) entry.getValue(), false, clock);
    }
}

class PublicClaimsIssuer implements ExpectedClaimType {
    private void assertValidIssuerClaim(String issuer, List<String> value) {
        if (issuer == null || !value.contains(issuer)) {
            throw new InvalidClaimException("The Claim 'iss' value doesn't match the required issuer.");
        }
    }

    @Override
    public void assertExpectedClaimType(DecodedJWT jwt, Map.Entry<String, Object> entry, Clock clock) {
        assertValidIssuerClaim(jwt.getIssuer(), (List<String>) entry.getValue());
    }
}

class PublicClaimsJwtId implements ExpectedClaimType {
    private void assertValidStringClaim(String claimName, String value, String expectedValue) {
        if (!expectedValue.equals(value)) {
            throw new InvalidClaimException(String.format("The Claim '%s' value doesn't match the required one.", claimName));
        }
    }
    @Override
    public void assertExpectedClaimType(DecodedJWT jwt, Map.Entry<String, Object> entry, Clock clock) {
        assertValidStringClaim(entry.getKey(), jwt.getId(), (String) entry.getValue());
    }
}

class PublicClaimsSubject implements ExpectedClaimType {
    private void assertValidStringClaim(String claimName, String value, String expectedValue) {
        if (!expectedValue.equals(value)) {
            throw new InvalidClaimException(String.format("The Claim '%s' value doesn't match the required one.", claimName));
        }
    }

    @Override
    public void assertExpectedClaimType(DecodedJWT jwt, Map.Entry<String, Object> entry, Clock clock) {
        assertValidStringClaim(entry.getKey(), jwt.getSubject(), (String) entry.getValue());
    }
}

class PublicClaimsDefault implements ExpectedClaimType {
    private boolean isAValidClaimObject(Claim claim, Object value) {
        boolean isValid;
        List<Object> claimArr;
        Object[] claimAsObject = claim.as(Object[].class);

        // Jackson uses 'natural' mapping which uses Integer if value fits in 32 bits.
        if (value instanceof Long[]) {
            // convert Integers to Longs for comparison with equals
            claimArr = new ArrayList<>(claimAsObject.length);
            for (Object cao : claimAsObject) {
                if (cao instanceof Integer) {
                    claimArr.add(((Integer) cao).longValue());
                } else {
                    claimArr.add(cao);
                }
            }
        } else {
            claimArr = claim.isNull() ? Collections.emptyList() : Arrays.asList(claim.as(Object[].class));
        }
        List<Object> valueArr = Arrays.asList((Object[]) value);
        isValid = claimArr.containsAll(valueArr);
        return isValid;
    }

    private void assertValidClaim(Claim claim, String claimName, Object value) {
        boolean isValid = false;
        if (value instanceof String) {
            isValid = value.equals(claim.asString());
        } else if (value instanceof Integer) {
            isValid = value.equals(claim.asInt());
        } else if (value instanceof Long) {
            isValid = value.equals(claim.asLong());
        } else if (value instanceof Boolean) {
            isValid = value.equals(claim.asBoolean());
        } else if (value instanceof Double) {
            isValid = value.equals(claim.asDouble());
        } else if (value instanceof Date) {
            isValid = value.equals(claim.asDate());
        } else if (value instanceof Object[]) {
            isValid = isAValidClaimObject(claim, value);
        }

        if (!isValid) {
            throw new InvalidClaimException(String.format("The Claim '%s' value doesn't match the required one.", claimName));
        }
    }

    @Override
    public void assertExpectedClaimType(DecodedJWT jwt, Map.Entry<String, Object> entry, Clock clock) {
        assertValidClaim(jwt.getClaim(entry.getKey()), entry.getKey(), entry.getValue());
    }
}

