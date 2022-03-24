package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.impl.JWTParser;
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
    final Map<String, BiPredicate<Claim, DecodedJWT>> expectedChecks;
    private final JWTParser parser;

    JWTVerifier(Algorithm algorithm, Map<String, BiPredicate<Claim, DecodedJWT>> expectedChecks) {
        this.algorithm = algorithm;
        this.expectedChecks = Collections.unmodifiableMap(expectedChecks);
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
        private final Map<String, BiPredicate<Claim, DecodedJWT>> expectedChecks;
        private long defaultLeeway;
        private final Map<String, Long> customLeeways;
        private boolean ignoreIssuedAt;
        private Clock clock;

        BaseVerification(Algorithm algorithm) throws IllegalArgumentException {
            if (algorithm == null) {
                throw new IllegalArgumentException("The Algorithm cannot be null.");
            }

            this.algorithm = algorithm;
            this.expectedChecks = new LinkedHashMap<>();
            this.customLeeways = new HashMap<>();
            this.defaultLeeway = 0;
        }

        @Override
        public Verification withIssuer(String... issuer) {
            List<String> value = isNullOrEmpty(issuer) ? null : Arrays.asList(issuer);
            checkIfNeedToRemove(PublicClaims.ISSUER, value, ((claim, decodedJWT) -> {
                if (value == null || !value.contains(claim.asString())) {
                    throw new InvalidClaimException("The Claim 'iss' value doesn't match the required issuer.");
                }
                return true;
            }));
            return this;
        }

        @Override
        public Verification withSubject(String subject) {
            checkIfNeedToRemove(PublicClaims.SUBJECT, subject, (claim, decodedJWT) -> subject.equals(claim.asString()));
            return this;
        }

        @Override
        public Verification withAudience(String... audience) {
            List<String> value = isNullOrEmpty(audience) ? null : Arrays.asList(audience);
            checkIfNeedToRemove(PublicClaims.AUDIENCE, value, ((claim, decodedJWT) ->
                    assertValidAudienceClaim(decodedJWT.getAudience(), value, true)));
            return this;
        }

        @Override
        public Verification withAnyOfAudience(String... audience) {
            List<String> value = isNullOrEmpty(audience) ? null : Arrays.asList(audience);
            checkIfNeedToRemove(PublicClaims.AUDIENCE, value, ((claim, decodedJWT) ->
                    assertValidAudienceClaim(decodedJWT.getAudience(), value, false)));
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
            customLeeways.put(PublicClaims.EXPIRES_AT, leeway);
            return this;
        }

        @Override
        public Verification acceptNotBefore(long leeway) throws IllegalArgumentException {
            assertPositive(leeway);
            customLeeways.put(PublicClaims.NOT_BEFORE, leeway);
            return this;
        }

        @Override
        public Verification acceptIssuedAt(long leeway) throws IllegalArgumentException {
            assertPositive(leeway);
            customLeeways.put(PublicClaims.ISSUED_AT, leeway);
            return this;
        }

        @Override
        public Verification ignoreIssuedAt() {
            this.ignoreIssuedAt = true;
            return this;
        }

        @Override
        public Verification withJWTId(String jwtId) {
            checkIfNeedToRemove(PublicClaims.JWT_ID, jwtId, ((claim, decodedJWT) -> jwtId.equals(claim.asString())));
            return this;
        }

        @Override
        public Verification withClaimPresence(String name) throws IllegalArgumentException {
            assertNonNull(name);
            withClaim(name, ((claim, decodedJWT) -> {
                if (claim.isMissing()) {
                    throw new InvalidClaimException(String.format("The Claim '%s' is not present in the JWT.", name));
                }
                return true;
            }));
            return this;
        }

        @Override
        public Verification withNullClaim(String name) throws IllegalArgumentException {
            assertNonNull(name);
            withClaim(name, ((claim, decodedJWT) -> claim.isNull()));
            return this;
        }

        @Override
        public Verification withClaim(String name, Boolean value) throws IllegalArgumentException {
            assertNonNull(name);
            checkIfNeedToRemove(name, value, ((claim, decodedJWT) -> value.equals(claim.asBoolean())));
            return this;
        }

        @Override
        public Verification withClaim(String name, Integer value) throws IllegalArgumentException {
            assertNonNull(name);
            checkIfNeedToRemove(name, value, ((claim, decodedJWT) -> value.equals(claim.asInt())));
            return this;
        }

        @Override
        public Verification withClaim(String name, Long value) throws IllegalArgumentException {
            assertNonNull(name);
            checkIfNeedToRemove(name, value, ((claim, decodedJWT) -> value.equals(claim.asLong())));
            return this;
        }

        @Override
        public Verification withClaim(String name, Double value) throws IllegalArgumentException {
            assertNonNull(name);
            checkIfNeedToRemove(name, value, ((claim, decodedJWT) -> value.equals(claim.asDouble())));
            return this;
        }

        @Override
        public Verification withClaim(String name, String value) throws IllegalArgumentException {
            assertNonNull(name);
            checkIfNeedToRemove(name, value, ((claim, decodedJWT) -> value.equals(claim.asString())));
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
            checkIfNeedToRemove(name, value,
                    ((claim, decodedJWT) -> value.truncatedTo(ChronoUnit.SECONDS).equals(claim.asInstant())));
            return this;
        }

        @Override
        public Verification withArrayClaim(String name, String... items) throws IllegalArgumentException {
            assertNonNull(name);
            checkIfNeedToRemove(name, items, ((claim, decodedJWT) -> assertValidCollectionClaim(claim, items)));
            return this;
        }

        @Override
        public Verification withArrayClaim(String name, Integer... items) throws IllegalArgumentException {
            assertNonNull(name);
            checkIfNeedToRemove(name, items, ((claim, decodedJWT) -> assertValidCollectionClaim(claim, items)));
            return this;
        }

        @Override
        public Verification withArrayClaim(String name, Long... items) throws IllegalArgumentException {
            assertNonNull(name);
            checkIfNeedToRemove(name, items, ((claim, decodedJWT) -> assertValidCollectionClaim(claim, items)));
            return this;
        }

        @Override
        public Verification withClaim(String name, BiPredicate<Claim, DecodedJWT> predicate) throws IllegalArgumentException {
            assertNonNull(name);
            checkIfNeedToRemove(name, predicate, predicate);
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
            this.clock = clock;
            addMandatoryClaimChecks();
            return new JWTVerifier(algorithm, expectedChecks);
        }

        /**
         * Fetches the Leeway set for claim or returns the {@link BaseVerification#defaultLeeway}
         *
         * @param name Claim for which leeway is fetched
         * @return Leeway value set for the claim
         */
        public long getLeewayFor(String name) {
            return customLeeways.getOrDefault(name, defaultLeeway);
        }

        private void addMandatoryClaimChecks() {
            long expiresAtLeeway = getLeewayFor(PublicClaims.EXPIRES_AT);
            long notBeforeLeeway = getLeewayFor(PublicClaims.NOT_BEFORE);
            long issuedAtLeeway = getLeewayFor(PublicClaims.ISSUED_AT);

            checkIfNeedToRemove(PublicClaims.EXPIRES_AT, expiresAtLeeway, ((claim, decodedJWT) ->
                    assertValidInstantClaim(claim.asInstant(), expiresAtLeeway, true)));
            checkIfNeedToRemove(PublicClaims.NOT_BEFORE, notBeforeLeeway, ((claim, decodedJWT) ->
                    assertValidInstantClaim(claim.asInstant(), notBeforeLeeway, false)));
            if (!ignoreIssuedAt) {
                checkIfNeedToRemove(PublicClaims.ISSUED_AT, issuedAtLeeway, ((claim, decodedJWT) ->
                        assertValidInstantClaim(claim.asInstant(), issuedAtLeeway, false)));
            }
        }

        private boolean assertValidCollectionClaim(Claim claim, Object[] expectedClaimValue) {
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
                claimArr = claim.isNull() || claim.isMissing() ?
                        Collections.emptyList() : Arrays.asList(claim.as(Object[].class));
            }
            List<Object> valueArr = Arrays.asList(expectedClaimValue);
            return claimArr.containsAll(valueArr);
        }

        private boolean assertValidInstantClaim(Instant claimVal, long leeway, boolean shouldBeFuture) {
            Instant now = clock.instant().truncatedTo(ChronoUnit.SECONDS);
            if (shouldBeFuture) {
                return assertInstantIsFuture(claimVal, leeway, now);
            } else {
                return assertInstantIsPast(claimVal, leeway, now);
            }
        }

        private boolean assertInstantIsFuture(Instant claimVal, long leeway, Instant now) {
            if (claimVal != null && now.minus(Duration.ofSeconds(leeway)).isAfter(claimVal)) {
                throw new TokenExpiredException(String.format("The Token has expired on %s.", claimVal));
            }
            return true;
        }

        private boolean assertInstantIsPast(Instant claimVal, long leeway, Instant now) {
            if (claimVal != null && now.plus(Duration.ofSeconds(leeway)).isBefore(claimVal)) {
                throw new InvalidClaimException(String.format("The Token can't be used before %s.", claimVal));
            }
            return true;
        }

        private boolean assertValidAudienceClaim(List<String> audience, List<String> values, boolean shouldContainAll) {
            if (audience == null || (shouldContainAll && !audience.containsAll(values)) ||
                    (!shouldContainAll && Collections.disjoint(audience, values))) {
                throw new InvalidClaimException("The Claim 'aud' value doesn't contain the required audience.");
            }
            return true;
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

        private void checkIfNeedToRemove(String name, Object value, BiPredicate<Claim, DecodedJWT> predicate) {
            if (value == null) {
                expectedChecks.remove(name);
                return;
            }
            expectedChecks.put(name, predicate);
        }

        private boolean isNullOrEmpty(String[] args) {
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
        verifyClaims(jwt, expectedChecks);
        return jwt;
    }

    private void verifyAlgorithm(DecodedJWT jwt, Algorithm expectedAlgorithm) throws AlgorithmMismatchException {
        if (!expectedAlgorithm.getName().equals(jwt.getAlgorithm())) {
            throw new AlgorithmMismatchException("The provided Algorithm doesn't match the one defined in the JWT's Header.");
        }
    }

    private void verifyClaims(DecodedJWT jwt, Map<String, BiPredicate<Claim, DecodedJWT>> claims) throws TokenExpiredException, InvalidClaimException {
        for (Map.Entry<String, BiPredicate<Claim, DecodedJWT>> entry : claims.entrySet()) {
            boolean isValid;
            String claimName = entry.getKey();
            BiPredicate<Claim, DecodedJWT> expectedCheck = entry.getValue();
            Claim claim = jwt.getClaim(claimName);

            isValid = expectedCheck.test(claim, jwt);

            if (!isValid) {
                throw new InvalidClaimException(String.format("The Claim '%s' value doesn't match the required one.", claimName));
            }
        }
    }
}
