package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.impl.PublicClaims;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * The JWTCreator class holds the sign method to generate a complete JWT (with Signature) from a given Header and Payload content.
 */
class JWTCreator {

    private final Algorithm algorithm;
    private final String headerJson;
    private final String payloadJson;

    private JWTCreator(Algorithm algorithm, Map<String, Object> headerClaims, Map<String, Object> payloadClaims) throws JWTCreationException {
        this.algorithm = algorithm;
        try {
            headerJson = toSafeJson(headerClaims);
            payloadJson = toSafeJson(payloadClaims);
        } catch (JsonProcessingException e) {
            throw new JWTCreationException("Some of the Claims couldn't be converted to a valid JSON format.", e);
        }
    }


    /**
     * Initialize a JWTCreator instance.
     *
     * @return a JWTCreator.Builder instance to configure.
     */
    static JWTCreator.Builder init() {
        return new Builder();
    }

    /**
     * The Builder class holds the Claims that defines the JWT to be created.
     */
    static class Builder {
        private final Map<String, Object> payloadClaims;
        private Map<String, Object> headerClaims;

        Builder() {
            this.payloadClaims = new HashMap<>();
            this.headerClaims = new HashMap<>();
        }

        /**
         * Add specific Claims to set as the Header.
         *
         * @return this same Builder instance.
         */
        public Builder withHeader(Map<String, Object> headerClaims) {
            this.headerClaims = new HashMap<>(headerClaims);
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
            //FIXME: Use a custom Serializer
            if (audience.length == 1) {
                addClaim(PublicClaims.AUDIENCE, audience[0]);
            } else if (audience.length > 1) {
                addClaim(PublicClaims.AUDIENCE, audience);
            }
            return this;
        }

        /**
         * Add a specific Expires At ("exp") claim.
         *
         * @return this same Builder instance.
         */
        public Builder withExpiresAt(Date expiresAt) {
            addClaim(PublicClaims.EXPIRES_AT, dateToSeconds(expiresAt));
            return this;
        }

        /**
         * Add a specific Not Before ("nbf") claim.
         *
         * @return this same Builder instance.
         */
        public Builder withNotBefore(Date notBefore) {
            addClaim(PublicClaims.NOT_BEFORE, dateToSeconds(notBefore));
            return this;
        }

        /**
         * Add a specific Issued At ("iat") claim.
         *
         * @return this same Builder instance.
         */
        public Builder withIssuedAt(Date issuedAt) {
            addClaim(PublicClaims.ISSUED_AT, dateToSeconds(issuedAt));
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
         * @param algorithm the Algorithm to use on the JWT signing.
         * @return a new JWT instance.
         * @throws IllegalArgumentException if the provided algorithm is null.
         * @throws JWTCreationException     if the Claims coudln't be converted to a valid JSON or there was a problem with the signing key.
         */
        public String sign(Algorithm algorithm) throws IllegalArgumentException, JWTCreationException {
            if (algorithm == null) {
                throw new IllegalArgumentException("The Algorithm cannot be null.");
            }
            headerClaims.put(PublicClaims.ALGORITHM, algorithm.getName());
            return new JWTCreator(algorithm, headerClaims, payloadClaims).sign();
        }

        private int dateToSeconds(Date date) {
            //FIXME: Use a custom Serializer
            return (int) (date.getTime() / 1000);
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
