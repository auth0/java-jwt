package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.impl.PublicClaims;

import java.util.*;

/**
 * The JWTVerifier class holds the verify method to assert that a given Token has not only a proper JWT format, but also it's signature matches.
 */
class JWTVerifier {
    private final Algorithm algorithm;
    final Map<String, Object> claims;
    private final Clock clock;

    private JWTVerifier(Algorithm algorithm, Map<String, Object> claims, Clock clock) {
        this.algorithm = algorithm;
        this.claims = Collections.unmodifiableMap(claims);
        this.clock = clock;
    }

    /**
     * Initialize a JWTVerifier instance using a HS Algorithm.
     *
     * @param algorithm the Algorithm to use on the JWT verification.
     * @return a JWTVerifier instance to configure.
     * @throws IllegalArgumentException if the provided algorithm is null.
     */
    static JWTVerifier.Verification init(Algorithm algorithm) throws IllegalArgumentException {
        return new Verification(algorithm);
    }

    /**
     * The Verification class holds the Claims required by a JWT to be valid.
     */
    static class Verification {
        private final Algorithm algorithm;
        private final Map<String, Object> claims;
        private long defaultDelta;

        Verification(Algorithm algorithm) throws IllegalArgumentException {
            if (algorithm == null) {
                throw new IllegalArgumentException("The Algorithm cannot be null.");
            }

            this.algorithm = algorithm;
            this.claims = new HashMap<>();
            this.defaultDelta = 0;
        }

        /**
         * Require a specific Issuer ("iss") claim.
         *
         * @return this same Verification instance.
         */
        public Verification withIssuer(String issuer) {
            requireClaim(PublicClaims.ISSUER, issuer);
            return this;
        }

        /**
         * Require a specific Subject ("sub") claim.
         *
         * @return this same Verification instance.
         */
        public Verification withSubject(String subject) {
            requireClaim(PublicClaims.SUBJECT, subject);
            return this;
        }

        /**
         * Require a specific Audience ("aud") claim.
         *
         * @return this same Verification instance.
         */
        public Verification withAudience(String[] audience) {
            requireClaim(PublicClaims.AUDIENCE, audience);
            return this;
        }

        /**
         * Define the default window in milliseconds in which the Not Before, Issued At and Expires At Claims will still be valid.
         * Setting a specific delta value on a given Claim will override this value for that Claim.
         *
         * @param delta the window in milliseconds in which the Not Before, Issued At and Expires At Claims will still be valid.
         * @return this same Verification instance.
         * @throws IllegalArgumentException if delta is negative.
         */
        public Verification acceptTimeDelta(long delta) throws IllegalArgumentException {
            if (delta < 0) {
                throw new IllegalArgumentException("Delta value can't be negative.");
            }
            this.defaultDelta = delta;
            return this;
        }

        /**
         * Set a specific delta window in milliseconds in which the Expires At ("exp") Claim will still be valid.
         * Expiration Date is always verified when the value is present. This method overrides the value set with acceptTimeDelta
         *
         * @param delta the window in milliseconds in which the Expires At Claim will still be valid.
         * @return this same Verification instance.
         * @throws IllegalArgumentException if delta is negative.
         */
        public Verification acceptExpiresAt(long delta) throws IllegalArgumentException {
            if (delta < 0) {
                throw new IllegalArgumentException("Delta value can't be negative.");
            }
            requireClaim(PublicClaims.EXPIRES_AT, delta);
            return this;
        }

        /**
         * Set a specific delta window in milliseconds in which the Not Before ("nbf") Claim will still be valid.
         * Not Before Date is always verified when the value is present. This method overrides the value set with acceptTimeDelta
         *
         * @param delta the window in milliseconds in which the Not Before Claim will still be valid.
         * @return this same Verification instance.
         * @throws IllegalArgumentException if delta is negative.
         */
        public Verification acceptNotBefore(long delta) throws IllegalArgumentException {
            if (delta < 0) {
                throw new IllegalArgumentException("Delta value can't be negative.");
            }
            requireClaim(PublicClaims.NOT_BEFORE, delta);
            return this;
        }

        /**
         * Set a specific delta window in milliseconds in which the Issued At ("iat") Claim will still be valid.
         * Issued At Date is always verified when the value is present. This method overrides the value set with acceptTimeDelta
         *
         * @param delta the window in milliseconds in which the Issued At Claim will still be valid.
         * @return this same Verification instance.
         * @throws IllegalArgumentException if delta is negative.
         */
        public Verification acceptIssuedAt(long delta) throws IllegalArgumentException {
            if (delta < 0) {
                throw new IllegalArgumentException("Delta value can't be negative.");
            }
            requireClaim(PublicClaims.ISSUED_AT, delta);
            return this;
        }

        /**
         * Require a specific JWT Id ("jti") claim.
         *
         * @return this same Verification instance.
         */
        public Verification withJWTId(String jwtId) {
            requireClaim(PublicClaims.JWT_ID, jwtId);
            return this;
        }

        /**
         * Creates a new and reusable instance of the JWTVerifier with the configuration already provided.
         *
         * @return a new JWTVerifier instance.
         */
        public JWTVerifier build() {
            return this.build(new Clock());
        }

        /**
         * Creates a new and reusable instance of the JWTVerifier with the configuration already provided.
         * ONLY FOR TEST PURPOSES.
         *
         * @param clock the instance that will handle the current time.
         * @return a new JWTVerifier instance with a custom Clock.
         */
        JWTVerifier build(Clock clock) {
            addDeltaToDateClaims();
            return new JWTVerifier(algorithm, claims, clock);
        }

        private void addDeltaToDateClaims() {
            if (!claims.containsKey(PublicClaims.EXPIRES_AT)) {
                claims.put(PublicClaims.EXPIRES_AT, defaultDelta);
            }
            if (!claims.containsKey(PublicClaims.NOT_BEFORE)) {
                claims.put(PublicClaims.NOT_BEFORE, defaultDelta);
            }
            if (!claims.containsKey(PublicClaims.ISSUED_AT)) {
                claims.put(PublicClaims.ISSUED_AT, defaultDelta);
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


    /**
     * Perform the verification against the given Token, using any previous configured options.
     *
     * @param token the String representation of the JWT.
     * @return a verified JWT.
     * @throws JWTDecodeException       if any part of the Token contained an invalid JWT or JSON format.
     * @throws JWTVerificationException if any of the required contents inside the JWT is invalid.
     */
    public JWT verify(String token) throws JWTDecodeException, JWTVerificationException {
        JWT jwt = new JWT(JWTDecoder.decode(token));
        verifyAlgorithm(jwt, algorithm);
        verifySignature(SignUtils.splitToken(token));
        verifyClaims(jwt, claims);
        return jwt;
    }

    private void verifySignature(String[] parts) throws SignatureVerificationException {
        algorithm.verify(parts);
    }

    private void verifyAlgorithm(JWT jwt, Algorithm expectedAlgorithm) throws AlgorithmMismatchException {
        if (!expectedAlgorithm.getName().equals(jwt.getAlgorithm())) {
            throw new AlgorithmMismatchException("The provided Algorithm doesn't match the one defined in the JWT's Header.");
        }
    }

    private void verifyClaims(JWT jwt, Map<String, Object> claims) {
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            assertValidClaim(jwt, entry.getKey(), entry.getValue());
        }
    }

    private void assertValidClaim(JWT jwt, String claimName, Object expectedValue) throws InvalidClaimException {
        String errMessage = String.format("The Claim '%s' value doesn't match the required one.", claimName);
        boolean isValid;
        if (PublicClaims.AUDIENCE.equals(claimName)) {
            isValid = Arrays.equals(jwt.getAudience(), (String[]) expectedValue);
        } else if (PublicClaims.NOT_BEFORE.equals(claimName) || PublicClaims.EXPIRES_AT.equals(claimName) || PublicClaims.ISSUED_AT.equals(claimName)) {
            long deltaValue = (long) expectedValue;
            Date today = clock.getToday();
            Date date = jwt.getClaim(claimName).asDate();
            if (PublicClaims.EXPIRES_AT.equals(claimName)) {
                today.setTime(today.getTime() - deltaValue);
                isValid = date == null || !today.after(date);
                errMessage = String.format("The Token has expired on %s.", date);
            } else {
                today.setTime(today.getTime() + deltaValue);
                isValid = date == null || !today.before(date);
                errMessage = String.format("The Token can't be used before %s.", date);
            }
        } else {
            String stringValue = (String) expectedValue;
            isValid = stringValue.equals(jwt.getClaim(claimName).asString());
        }

        if (!isValid) {
            throw new InvalidClaimException(errMessage);
        }
    }
}
