package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.Clock;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * The JWTVerifier class holds the verify method to assert that a given Token has not only a proper JWT format, but also it's signature matches.
 * <p>
 * This class is thread-safe.
 */
@SuppressWarnings("WeakerAccess")
public final class JWTVerifier implements com.auth0.jwt.interfaces.JWTVerifier {
    private final Algorithm algorithm;
    final Map<String, Object> claims;
    private final Clock clock;
    private final JWTParser parser;

    JWTVerifier(Algorithm algorithm, Map<String, Object> claims, Clock clock) {
        this.algorithm = algorithm;
        this.claims = Collections.unmodifiableMap(claims);
        this.clock = clock;
        this.parser = new JWTParser();
    }

    /**
     * Initialize a JWTVerifier instance using the given Algorithm.
     *
     * @param algorithm the Algorithm to use on the JWT verification.
     * @return a JWTVerifier.Verification instance to configure.
     * @throws IllegalArgumentException if the provided algorithm is null.
     */
    static Verification init(Algorithm algorithm) throws IllegalArgumentException {
        return new BaseVerification(algorithm);
    }

    public static class BaseVerification implements Verification {
        private final Algorithm algorithm;
        private final Map<String, Object> claims;
        private long defaultLeeway;
        private boolean ignoreIssuedAt;

        BaseVerification(Algorithm algorithm) throws IllegalArgumentException {
            if (algorithm == null) {
                throw new IllegalArgumentException("The Algorithm cannot be null.");
            }

            this.algorithm = algorithm;
            this.claims = new HashMap<>();
            this.defaultLeeway = 0;
        }

        @Override
        public Verification withIssuer(String... issuer) {
            requireClaim(PublicClaims.ISSUER, isNullOrEmpty(issuer) ? null : Arrays.asList(issuer));
            return this;
        }

        @Override
        public Verification withSubject(String subject) {
            requireClaim(PublicClaims.SUBJECT, subject);
            return this;
        }

        @Override
        public Verification withAudience(String... audience) {
            requireClaim(PublicClaims.AUDIENCE, isNullOrEmpty(audience) ? null : Arrays.asList(audience));
            return this;
        }

        @Override
        public Verification acceptLeeway(long leeway) throws IllegalArgumentException {
            assertPositive(leeway);
            this.defaultLeeway = leeway;
            return this;
        }

        @Override
        public Verification acceptExpiresAt(long leeway) throws IllegalArgumentException {
            assertPositive(leeway);
            requireClaim(PublicClaims.EXPIRES_AT, leeway);
            return this;
        }

        @Override
        public Verification acceptNotBefore(long leeway) throws IllegalArgumentException {
            assertPositive(leeway);
            requireClaim(PublicClaims.NOT_BEFORE, leeway);
            return this;
        }

        @Override
        public Verification acceptIssuedAt(long leeway) throws IllegalArgumentException {
            assertPositive(leeway);
            requireClaim(PublicClaims.ISSUED_AT, leeway);
            return this;
        }

        @Override
        public Verification ignoreIssuedAt() {
            this.ignoreIssuedAt = true;
            return this;
        }

        @Override
        public Verification withJWTId(String jwtId) {
            requireClaim(PublicClaims.JWT_ID, jwtId);
            return this;
        }

        @Override
        public Verification withClaim(String name, Boolean value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        @Override
        public Verification withClaim(String name, Integer value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        @Override
        public Verification withClaim(String name, Long value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        @Override
        public Verification withClaim(String name, Double value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        @Override
        public Verification withClaim(String name, String value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        @Override
        public Verification withClaim(String name, Instant value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        @Override
        public Verification withClaim(String name, Date value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        @Override
        public Verification withArrayClaim(String name, String... items) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, items);
            return this;
        }

        @Override
        public Verification withArrayClaim(String name, Integer... items) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, items);
            return this;
        }

        @Override
        public Verification withArrayClaim(String name, Long... items) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, items);
            return this;
        }

        @Override
        public JWTVerifier build() {
            return this.build(new ClockImpl());
        }

        /**
         * Creates a new and reusable instance of the JWTVerifier with the configuration already provided.
         * ONLY FOR TEST PURPOSES.
         *
         * @param clock the instance that will handle the current time.
         * @return a new JWTVerifier instance with a custom Clock.
         */
        public JWTVerifier build(Clock clock) {
            addLeewayToDateClaims();
            return new JWTVerifier(algorithm, claims, clock);
        }

        private void assertPositive(long leeway) {
            if (leeway < 0) {
                throw new IllegalArgumentException("Leeway value can't be negative.");
            }
        }

        private void assertNonNull(String name) {
            if (name == null) {
                throw new IllegalArgumentException("The Custom Claim's name can't be null.");
            }
        }

        private void addLeewayToDateClaims() {
            if (!claims.containsKey(PublicClaims.EXPIRES_AT)) {
                claims.put(PublicClaims.EXPIRES_AT, defaultLeeway);
            }
            if (!claims.containsKey(PublicClaims.NOT_BEFORE)) {
                claims.put(PublicClaims.NOT_BEFORE, defaultLeeway);
            }
            if (ignoreIssuedAt) {
                claims.remove(PublicClaims.ISSUED_AT);
                return;
            }
            if (!claims.containsKey(PublicClaims.ISSUED_AT)) {
                claims.put(PublicClaims.ISSUED_AT, defaultLeeway);
            }
        }

        private void requireClaim(String name, Object value) {
            if (value == null) {
                claims.remove(name);
                return;
            }
            claims.put(name, value);
        }
    }

    private static boolean isNullOrEmpty(String[] args) {
        if (args == null || args.length == 0) {
            return true;
        }
        boolean isAllNull = true;
        for (String arg : args) {
            if (arg != null) {
                isAllNull = false;
                break;
            }
        }
        return isAllNull;
    }


    /**
     * Perform the verification against the given Token, using any previous configured options.
     *
     * @param token to verify.
     * @return a verified and decoded JWT.
     * @throws AlgorithmMismatchException     if the algorithm stated in the token's header it's not equal to the one defined in the {@link JWTVerifier}.
     * @throws SignatureVerificationException if the signature is invalid.
     * @throws TokenExpiredException          if the token has expired.
     * @throws InvalidClaimException          if a claim contained a different value than the expected one.
     */
    @Override
    public DecodedJWT verify(String token) throws JWTVerificationException {
        DecodedJWT jwt = new JWTDecoder(parser, token);
        return verify(jwt);
    }

    /**
     * Perform the verification against the given decoded JWT, using any previous configured options.
     *
     * @param jwt to verify.
     * @return a verified and decoded JWT.
     * @throws AlgorithmMismatchException     if the algorithm stated in the token's header it's not equal to the one defined in the {@link JWTVerifier}.
     * @throws SignatureVerificationException if the signature is invalid.
     * @throws TokenExpiredException          if the token has expired.
     * @throws InvalidClaimException          if a claim contained a different value than the expected one.
     */
    @Override
    public DecodedJWT verify(DecodedJWT jwt) throws JWTVerificationException {
        verifyAlgorithm(jwt, algorithm);
        algorithm.verify(jwt);
        verifyClaims(jwt, claims);
        return jwt;
    }

    private void verifyAlgorithm(DecodedJWT jwt, Algorithm expectedAlgorithm) throws AlgorithmMismatchException {
        if (!expectedAlgorithm.getName().equals(jwt.getAlgorithm())) {
            throw new AlgorithmMismatchException("The provided Algorithm doesn't match the one defined in the JWT's Header.");
        }
    }

    private void verifyClaims(DecodedJWT jwt, Map<String, Object> claims) throws TokenExpiredException, InvalidClaimException {
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            switch (entry.getKey()) {
                case PublicClaims.AUDIENCE:
                    assertValidAudienceClaim(jwt.getAudience(), (List<String>) entry.getValue());
                    break;
                case PublicClaims.EXPIRES_AT:
                    assertValidInstantClaim(jwt.getExpiresAtInstant(), (Long) entry.getValue(), true);
                    break;
                case PublicClaims.ISSUED_AT:
                    assertValidInstantClaim(jwt.getIssuedAtInstant(), (Long) entry.getValue(), false);
                    break;
                case PublicClaims.NOT_BEFORE:
                    assertValidInstantClaim(jwt.getNotBeforeInstant(), (Long) entry.getValue(), false);
                    break;
                case PublicClaims.ISSUER:
                    assertValidIssuerClaim(jwt.getIssuer(), (List<String>) entry.getValue());
                    break;
                case PublicClaims.JWT_ID:
                    assertValidStringClaim(entry.getKey(), jwt.getId(), (String) entry.getValue());
                    break;
                case PublicClaims.SUBJECT:
                    assertValidStringClaim(entry.getKey(), jwt.getSubject(), (String) entry.getValue());
                    break;
                default:
                    assertValidClaim(jwt.getClaim(entry.getKey()), entry.getKey(), entry.getValue());
                    break;
            }
        }
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
        } else if (value instanceof Instant) {
            isValid = value.equals(claim.asInstant());
        } else if (value instanceof Object[]) {
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
        }

        if (!isValid) {
            throw new InvalidClaimException(String.format("The Claim '%s' value doesn't match the required one.", claimName));
        }
    }

    private void assertValidStringClaim(String claimName, String value, String expectedValue) {
        if (!expectedValue.equals(value)) {
            throw new InvalidClaimException(String.format("The Claim '%s' value doesn't match the required one.", claimName));
        }
    }

    private void assertValidInstantClaim(Instant claimVal, long leeway, boolean shouldBeFuture) {
        Instant today = clock.getNow();
        if (shouldBeFuture) {
            assertInstantIsFuture(claimVal, leeway, today);
        } else {
            assertInstantIsPast(claimVal, leeway, today);
        }
    }

    private void assertInstantIsFuture(Instant claimVal, long leeway, Instant now) {
        if (claimVal != null && now.minus(Duration.ofSeconds(leeway)).isAfter(claimVal)) {
            throw new TokenExpiredException(String.format("The Token has expired on %s.", claimVal));
        }
    }

    private void assertInstantIsPast(Instant claimVal, long leeway, Instant now) {
        if (claimVal != null && now.plus(Duration.ofSeconds(leeway)).isBefore(claimVal)) {
            throw new InvalidClaimException(String.format("The Token can't be used before %s.", claimVal));
        }
    }

    private void assertValidAudienceClaim(List<String> audience, List<String> value) {
        if (audience == null || !audience.containsAll(value)) {
            throw new InvalidClaimException("The Claim 'aud' value doesn't contain the required audience.");
        }
    }

    private void assertValidIssuerClaim(String issuer, List<String> value) {
        if (issuer == null || !value.contains(issuer)) {
            throw new InvalidClaimException("The Claim 'iss' value doesn't match the required issuer.");
        }
    }
}
