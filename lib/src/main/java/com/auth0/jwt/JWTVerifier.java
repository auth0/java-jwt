package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.impl.NullClaim;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.function.BiPredicate;

/**
 * The JWTVerifier class holds the verify method to assert that a given Token has not only a proper JWT format, but also its signature matches.
 * <p>
 * This class is thread-safe.
 */
@SuppressWarnings("WeakerAccess")
public final class JWTVerifier implements com.auth0.jwt.interfaces.JWTVerifier {
    private final Algorithm algorithm;
    final Map<String, Object> expectedClaims;
    private final Clock clock;
    private final JWTParser parser;

    static final String AUDIENCE_EXACT = "AUDIENCE_EXACT";
    static final String AUDIENCE_CONTAINS = "AUDIENCE_CONTAINS";

    JWTVerifier(Algorithm algorithm, Map<String, Object> expectedClaims, Clock clock) {
        this.algorithm = algorithm;
        this.expectedClaims = Collections.unmodifiableMap(expectedClaims);
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
        private final Map<String, Object> expectedClaims;
        private long defaultLeeway;
        private boolean ignoreIssuedAt;

        BaseVerification(Algorithm algorithm) throws IllegalArgumentException {
            if (algorithm == null) {
                throw new IllegalArgumentException("The Algorithm cannot be null.");
            }

            this.algorithm = algorithm;
            this.expectedClaims = new HashMap<>();
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
            expectedClaims.remove(AUDIENCE_CONTAINS);
            requireClaim(AUDIENCE_EXACT, isNullOrEmpty(audience) ? null : Arrays.asList(audience));
            return this;
        }

        @Override
        public Verification withAnyOfAudience(String... audience) {
            expectedClaims.remove(AUDIENCE_EXACT);
            requireClaim(AUDIENCE_CONTAINS, isNullOrEmpty(audience) ? null : Arrays.asList(audience));
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
        public Verification withClaimPresence(String name) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, NonEmptyClaim.getInstance());
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
        public Verification withClaim(String name, Date value) throws IllegalArgumentException {
            return withClaim(name, value != null ? value.toInstant() : null);
        }

        @Override
        public Verification withClaim(String name, Instant value) throws IllegalArgumentException {
            assertNonNull(name);
            // Since date-time claims are serialized as epoch seconds, we need to compare them with only seconds-granularity
            requireClaim(name, value != null ? value.truncatedTo(ChronoUnit.SECONDS) : null);
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
        public Verification withClaim(String name, BiPredicate<Claim, DecodedJWT> predicate) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, predicate);
            return this;
        }

        @Override
        public JWTVerifier build() {
            return this.build(Clock.systemUTC());
        }

        /**
         * Creates a new and reusable instance of the JWTVerifier with the configuration already provided.
         * ONLY FOR TEST PURPOSES.
         *
         * @param clock the instance that will handle the current time.
         * @return a new JWTVerifier instance with a custom {@link java.time.Clock}
         */
        public JWTVerifier build(Clock clock) {
            addLeewayToDateClaims();
            return new JWTVerifier(algorithm, expectedClaims, clock);
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
            if (!expectedClaims.containsKey(PublicClaims.EXPIRES_AT)) {
                expectedClaims.put(PublicClaims.EXPIRES_AT, defaultLeeway);
            }
            if (!expectedClaims.containsKey(PublicClaims.NOT_BEFORE)) {
                expectedClaims.put(PublicClaims.NOT_BEFORE, defaultLeeway);
            }
            if (ignoreIssuedAt) {
                expectedClaims.remove(PublicClaims.ISSUED_AT);
                return;
            }
            if (!expectedClaims.containsKey(PublicClaims.ISSUED_AT)) {
                expectedClaims.put(PublicClaims.ISSUED_AT, defaultLeeway);
            }
        }

        private void requireClaim(String name, Object value) {
            if (value == null) {
                expectedClaims.remove(name);
                return;
            }
            expectedClaims.put(name, value);
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
     * @throws AlgorithmMismatchException     if the algorithm stated in the token's header is not equal to the one defined in the {@link JWTVerifier}.
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
     * @throws AlgorithmMismatchException     if the algorithm stated in the token's header is not equal to the one defined in the {@link JWTVerifier}.
     * @throws SignatureVerificationException if the signature is invalid.
     * @throws TokenExpiredException          if the token has expired.
     * @throws InvalidClaimException          if a claim contained a different value than the expected one.
     */
    @Override
    public DecodedJWT verify(DecodedJWT jwt) throws JWTVerificationException {
        verifyAlgorithm(jwt, algorithm);
        algorithm.verify(jwt);
        verifyClaims(jwt, expectedClaims);
        return jwt;
    }

    private void verifyAlgorithm(DecodedJWT jwt, Algorithm expectedAlgorithm) throws AlgorithmMismatchException {
        if (!expectedAlgorithm.getName().equals(jwt.getAlgorithm())) {
            throw new AlgorithmMismatchException("The provided Algorithm doesn't match the one defined in the JWT's Header.");
        }
    }

    private void verifyClaims(DecodedJWT jwt, Map<String, Object> claims) throws TokenExpiredException, InvalidClaimException {
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            if (entry.getValue() instanceof NonEmptyClaim) {
                assertClaimPresent(jwt.getClaim(entry.getKey()), entry.getKey());
            } else {
                verifyClaimValues(jwt, entry);
            }
        }
    }

    private void verifyClaimValues(DecodedJWT jwt, Map.Entry<String, Object> expectedClaim) {
        switch (expectedClaim.getKey()) {
            // We use custom keys for audience in the expected claims to differentiate between validating that the audience
            // contains all expected values, or validating that the audience contains at least one of the expected values.
            case AUDIENCE_EXACT:
                assertValidAudienceClaim(jwt.getAudience(), (List<String>) expectedClaim.getValue(), true);
                break;
            case AUDIENCE_CONTAINS:
                assertValidAudienceClaim(jwt.getAudience(), (List<String>) expectedClaim.getValue(), false);
                break;
            case PublicClaims.EXPIRES_AT:
                assertValidInstantClaim(jwt.getExpiresAtAsInstant(), (Long) expectedClaim.getValue(), true);
                break;
            case PublicClaims.ISSUED_AT:
                assertValidInstantClaim(jwt.getIssuedAtAsInstant(), (Long) expectedClaim.getValue(), false);
                break;
            case PublicClaims.NOT_BEFORE:
                assertValidInstantClaim(jwt.getNotBeforeAsInstant(), (Long) expectedClaim.getValue(), false);
                break;
            case PublicClaims.ISSUER:
                assertValidIssuerClaim(jwt.getIssuer(), (List<String>) expectedClaim.getValue());
                break;
            case PublicClaims.JWT_ID:
                assertValidStringClaim(expectedClaim.getKey(), jwt.getId(), (String) expectedClaim.getValue());
                break;
            case PublicClaims.SUBJECT:
                assertValidStringClaim(expectedClaim.getKey(), jwt.getSubject(), (String) expectedClaim.getValue());
                break;
            default:
                assertValidClaim(jwt, expectedClaim);
                break;
        }
    }

    private void assertClaimPresent(Claim claim, String claimName) {
        if (claim instanceof NullClaim) {
            throw new InvalidClaimException(String.format("The Claim '%s' is not present in the JWT.", claimName));
        }
    }

    private void assertValidClaim(DecodedJWT jwt, Map.Entry<String, Object> expectedClaim) {
        boolean isValid = false;
        String claimName = expectedClaim.getKey();
        Object expectedClaimValue = expectedClaim.getValue();
        Claim claim = jwt.getClaim(claimName);

        if (expectedClaimValue instanceof String) {
            isValid = expectedClaimValue.equals(claim.asString());
        } else if (expectedClaimValue instanceof Integer) {
            isValid = expectedClaimValue.equals(claim.asInt());
        } else if (expectedClaimValue instanceof Long) {
            isValid = expectedClaimValue.equals(claim.asLong());
        } else if (expectedClaimValue instanceof Boolean) {
            isValid = expectedClaimValue.equals(claim.asBoolean());
        } else if (expectedClaimValue instanceof Double) {
            isValid = expectedClaimValue.equals(claim.asDouble());
        } else if (expectedClaimValue instanceof Instant) {
            isValid = expectedClaimValue.equals(claim.asInstant());
        } else if (expectedClaimValue instanceof BiPredicate) {
            isValid = ((BiPredicate) expectedClaimValue).test(claim, jwt);
        } else if (expectedClaimValue instanceof Object[]) {
            List<Object> claimArr;
            Object[] claimAsObject = claim.as(Object[].class);

            // Jackson uses 'natural' mapping which uses Integer if value fits in 32 bits.
            if (expectedClaimValue instanceof Long[]) {
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
            List<Object> valueArr = Arrays.asList((Object[]) expectedClaimValue);
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
        Instant now = clock.instant().truncatedTo(ChronoUnit.SECONDS);
        if (shouldBeFuture) {
            assertInstantIsFuture(claimVal, leeway, now);
        } else {
            assertInstantIsPast(claimVal, leeway, now);
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

    private void assertValidAudienceClaim(List<String> audience, List<String> values, boolean shouldContainAll) {
        if (audience == null || (shouldContainAll && !audience.containsAll(values)) ||
                (!shouldContainAll && Collections.disjoint(audience, values))) {
            throw new InvalidClaimException("The Claim 'aud' value doesn't contain the required audience.");
        }
    }

    private void assertValidIssuerClaim(String issuer, List<String> value) {
        if (issuer == null || !value.contains(issuer)) {
            throw new InvalidClaimException("The Claim 'iss' value doesn't match the required issuer.");
        }
    }

    /**
     * Simple singleton used to mark that a claim should only be verified for presence.
     */
    private static class NonEmptyClaim {
        private static NonEmptyClaim nonEmptyClaim;

        private NonEmptyClaim() {}

        public static NonEmptyClaim getInstance() {
            if (nonEmptyClaim == null) {
                nonEmptyClaim = new NonEmptyClaim();
            }
            return nonEmptyClaim;
        }
    }
}
