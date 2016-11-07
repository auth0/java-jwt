package com.auth0.jwtdecodejava;

import com.auth0.jwtdecodejava.algorithms.Algorithm;
import com.auth0.jwtdecodejava.exceptions.*;
import com.auth0.jwtdecodejava.impl.PublicClaims;

import java.util.*;

/**
 * The JWTVerifier class holds the verify method to assert that a given Token has not only a proper JWT format, but also it's signature matches.
 */
class JWTVerifier {
    private final Algorithm algorithm;
    final Map<String, Object> claims;

    private JWTVerifier(Algorithm algorithm, Map<String, Object> claims) {
        this.algorithm = algorithm;
        this.claims = Collections.unmodifiableMap(claims);
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

        Verification(Algorithm algorithm) throws IllegalArgumentException {
            if (algorithm == null) {
                throw new IllegalArgumentException("The Algorithm cannot be null.");
            }

            this.algorithm = algorithm;
            this.claims = new HashMap<>();
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
         * Require a specific Expires At ("exp") claim.
         *
         * @return this same Verification instance.
         */
        public Verification withExpiresAt(Date expiresAt) {
            requireClaim(PublicClaims.EXPIRES_AT, expiresAt);
            return this;
        }

        /**
         * Require a specific Not Before ("nbf") claim.
         *
         * @return this same Verification instance.
         */
        public Verification withNotBefore(Date notBefore) {
            requireClaim(PublicClaims.NOT_BEFORE, notBefore);
            return this;
        }

        /**
         * Require a specific Issued At ("iat") claim.
         *
         * @return this same Verification instance.
         */
        public Verification withIssuedAt(Date issuedAt) {
            requireClaim(PublicClaims.ISSUED_AT, issuedAt);
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
            return new JWTVerifier(algorithm, claims);
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
        boolean isValid;
        if (PublicClaims.AUDIENCE.equals(claimName)) {
            isValid = Arrays.equals(jwt.getAudience(), (String[]) expectedValue);
        } else if (PublicClaims.NOT_BEFORE.equals(claimName) || PublicClaims.EXPIRES_AT.equals(claimName) || PublicClaims.ISSUED_AT.equals(claimName)) {
            Date dateValue = (Date) expectedValue;
            isValid = dateValue.equals(jwt.getClaim(claimName).asDate());
        } else {
            String stringValue = (String) expectedValue;
            isValid = stringValue.equals(jwt.getClaim(claimName).asString());
        }

        if (!isValid) {
            throw new InvalidClaimException(String.format("The Claim '%s' value doesn't match the required one.", claimName));
        }
    }
}
