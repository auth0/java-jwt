package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.impl.PublicClaims;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

class JWTCreator {

    private final Algorithm algorithm;
    private final String headerJson;
    private final String payloadJson;

    private JWTCreator(Algorithm algorithm, Map<String, Object> headerClaims, Map<String, Object> payloadClaims) throws JWTCreationException {
        this.algorithm = algorithm;
        headerClaims.put(PublicClaims.ALGORITHM, algorithm.getName());
        try {
            headerJson = toSafeJson(headerClaims);
            payloadJson = toSafeJson(payloadClaims);
        } catch (JsonProcessingException e) {
            throw new JWTCreationException("Some of the Claims couldn't be converted to a valid JSON format.", e);
        }
    }


    /**
     * Initialize a JWTCreator instance using the given Algorithm.
     *
     * @param algorithm the Algorithm to use on the JWT signing.
     * @return a JWTCreator.Builder instance to configure.
     * @throws IllegalArgumentException if the provided algorithm is null.
     */
    static JWTCreator.Builder init(Algorithm algorithm) throws IllegalArgumentException {
        return new Builder(algorithm);
    }

    /**
     * The Builder class holds the Claims required by a JWT to be valid.
     */
    static class Builder {
        private final Algorithm algorithm;
        private final Map<String, Object> payloadClaims;
        private Map<String, Object> headerClaims;

        Builder(Algorithm algorithm) throws IllegalArgumentException {
            if (algorithm == null) {
                throw new IllegalArgumentException("The Algorithm cannot be null.");
            }

            this.algorithm = algorithm;
            this.payloadClaims = new HashMap<>();
            this.headerClaims = new HashMap<>();
        }

        /**
         * Add specific Claims to set as the Header.
         *
         * @return this same Builder instance.
         */
        public Builder withHeader(Map<String, Object> headerClaims) {
            this.headerClaims = Collections.unmodifiableMap(headerClaims);
            return this;
        }

        /**
         * Add a specific Issuer ("iss") claim.
         *
         * @return this same Builder instance.
         */
        public Builder withIssuer(String issuer) {
            addClaim(PublicClaims.ISSUER, issuer);
            return this;
        }

        /**
         * Add a specific Subject ("sub") claim.
         *
         * @return this same Builder instance.
         */
        public Builder withSubject(String subject) {
            addClaim(PublicClaims.SUBJECT, subject);
            return this;
        }

        /**
         * Add a specific Audience ("aud") claim.
         *
         * @return this same Builder instance.
         */
        public Builder withAudience(String[] audience) {
            addClaim(PublicClaims.AUDIENCE, audience);
            return this;
        }

        /**
         * Add a specific Expires At ("exp") claim.
         *
         * @return this same Builder instance.
         */
        public Builder withExpiresAt(Date expiresAt) {
            addClaim(PublicClaims.EXPIRES_AT, expiresAt);
            return this;
        }

        /**
         * Add a specific Not Before ("nbf") claim.
         *
         * @return this same Builder instance.
         */
        public Builder withNotBefore(Date notBefore) {
            addClaim(PublicClaims.NOT_BEFORE, notBefore);
            return this;
        }

        /**
         * Add a specific Issued At ("iat") claim.
         *
         * @return this same Builder instance.
         */
        public Builder withIssuedAt(Date issuedAt) {
            addClaim(PublicClaims.ISSUED_AT, issuedAt);
            return this;
        }

        /**
         * Add a specific JWT Id ("jti") claim.
         *
         * @return this same Builder instance.
         */
        public Builder withJWTId(String jwtId) {
            addClaim(PublicClaims.JWT_ID, jwtId);
            return this;
        }

        /**
         * Creates a new instance of the JWT with the specified payloadClaims.
         *
         * @return a new JWT instance.
         */
        public String sign() throws JWTCreationException {
            return new JWTCreator(algorithm, headerClaims, payloadClaims).sign();
        }

        private void addClaim(String name, Object value) {
            if (value == null) {
                payloadClaims.remove(name);
                return;
            }
            payloadClaims.put(name, value);
        }
    }

    private String toSafeJson(Map<String, Object> claims) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(claims);
    }

    private String sign() throws SignatureGenerationException {
        String header = SignUtils.base64Encode(headerJson.getBytes());
        String payload = SignUtils.base64Encode(payloadJson.getBytes());
        String content = String.format("%s.%s", header, payload);

        byte[] signatureBytes = algorithm.sign(content.getBytes());
        String signature = SignUtils.base64Encode(signatureBytes);

        return String.format("%s.%s", content, signature);
    }
}
