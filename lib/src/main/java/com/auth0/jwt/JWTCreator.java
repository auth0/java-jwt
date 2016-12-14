package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.impl.ClaimsHolder;
import com.auth0.jwt.impl.PayloadSerializer;
import com.auth0.jwt.impl.PublicClaims;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.apache.commons.codec.binary.Base64;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * The JWTCreator class holds the sign method to generate a complete JWT (with Signature) from a given Header and Payload content.
 */
@SuppressWarnings("WeakerAccess")
public final class JWTCreator {

    private final Algorithm algorithm;
    private final String headerJson;
    private final String payloadJson;

    private JWTCreator(Algorithm algorithm, Map<String, Object> headerClaims, Map<String, Object> payloadClaims) throws JWTCreationException {
        this.algorithm = algorithm;
        try {
            ObjectMapper mapper = new ObjectMapper();
            SimpleModule module = new SimpleModule();
            module.addSerializer(ClaimsHolder.class, new PayloadSerializer());
            mapper.registerModule(module);
            headerJson = mapper.writeValueAsString(headerClaims);
            payloadJson = mapper.writeValueAsString(new ClaimsHolder(payloadClaims));
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
    public static class Builder {
        private final Map<String, Object> payloadClaims;
        private Map<String, Object> headerClaims;

        Builder() {
            this.payloadClaims = new HashMap<>();
            this.headerClaims = new HashMap<>();
        }

        /**
         * Add specific Claims to set as the Header.
         *
         * @param headerClaims the values to use as Claims in the token's Header.
         * @return this same Builder instance.
         */
        public Builder withHeader(Map<String, Object> headerClaims) {
            this.headerClaims = new HashMap<>(headerClaims);
            return this;
        }

        /**
         * Add a specific Issuer ("iss") claim.
         *
         * @param issuer the Issuer value.
         * @return this same Builder instance.
         */
        public Builder withIssuer(String issuer) {
            addClaim(PublicClaims.ISSUER, issuer);
            return this;
        }

        /**
         * Add a specific Subject ("sub") claim.
         *
         * @param subject the Subject value.
         * @return this same Builder instance.
         */
        public Builder withSubject(String subject) {
            addClaim(PublicClaims.SUBJECT, subject);
            return this;
        }

        /**
         * Add a specific Audience ("aud") claim.
         *
         * @param audience the Audience value.
         * @return this same Builder instance.
         */
        public Builder withAudience(String... audience) {
            addClaim(PublicClaims.AUDIENCE, audience);
            return this;
        }

        /**
         * Add a specific Expires At ("exp") claim.
         *
         * @param expiresAt the Expires At value.
         * @return this same Builder instance.
         */
        public Builder withExpiresAt(Date expiresAt) {
            addClaim(PublicClaims.EXPIRES_AT, expiresAt);
            return this;
        }

        /**
         * Add a specific Not Before ("nbf") claim.
         *
         * @param notBefore the Not Before value.
         * @return this same Builder instance.
         */
        public Builder withNotBefore(Date notBefore) {
            addClaim(PublicClaims.NOT_BEFORE, notBefore);
            return this;
        }

        /**
         * Add a specific Issued At ("iat") claim.
         *
         * @param issuedAt the Issued At value.
         * @return this same Builder instance.
         */
        public Builder withIssuedAt(Date issuedAt) {
            addClaim(PublicClaims.ISSUED_AT, issuedAt);
            return this;
        }

        /**
         * Add a specific JWT Id ("jti") claim.
         *
         * @param jwtId the Token Id value.
         * @return this same Builder instance.
         */
        public Builder withJWTId(String jwtId) {
            addClaim(PublicClaims.JWT_ID, jwtId);
            return this;
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public Builder withClaim(String name, Object value) throws IllegalArgumentException {
            if (name == null) {
                throw new IllegalArgumentException("The Custom Claim's name can't be null.");
            }

            addClaim(name, value);
            return this;
        }

        /**
         * Creates a new JWT and signs is with the given algorithm
         *
         * @param algorithm used to sign the JWT
         * @return a new JWT token
         * @throws IllegalArgumentException if the provided algorithm is null.
         * @throws JWTCreationException     if the claims could not be converted to a valid JSON or there was a problem with the signing key.
         */
        public String sign(Algorithm algorithm) throws IllegalArgumentException, JWTCreationException {
            if (algorithm == null) {
                throw new IllegalArgumentException("The Algorithm cannot be null.");
            }
            headerClaims.put(PublicClaims.ALGORITHM, algorithm.getName());
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

    private String sign() throws SignatureGenerationException {
        String header = Base64.encodeBase64URLSafeString((headerJson.getBytes(StandardCharsets.UTF_8)));
        String payload = Base64.encodeBase64URLSafeString((payloadJson.getBytes(StandardCharsets.UTF_8)));
        String content = String.format("%s.%s", header, payload);

        byte[] signatureBytes = algorithm.sign(content.getBytes(StandardCharsets.UTF_8));
        String signature = Base64.encodeBase64URLSafeString((signatureBytes));

        return String.format("%s.%s", content, signature);
    }
}
