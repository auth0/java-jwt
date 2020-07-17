package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.impl.ClaimsHolder;
import com.auth0.jwt.impl.PayloadSerializer;
import com.auth0.jwt.impl.PublicClaims;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.apache.commons.codec.binary.Base64;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * The JWTCreator class holds the sign method to generate a complete JWT (with Signature) from a given Header and Payload content.
 * <p>
 * This class is thread-safe.
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
            mapper.configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true);
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
    @NotNull
    static JWTCreator.Builder init() {
        return new Builder();
    }

    /**
     * The Builder class holds the Claims that defines the JWT to be created.
     */
    public static class Builder {
        private final Map<String, Object> payloadClaims;
        private final Map<String, Object> headerClaims;

        Builder() {
            this.payloadClaims = new HashMap<>();
            this.headerClaims = new HashMap<>();
        }

        /**
         * Add specific Claims to set as the Header.
         * If provided map is null then nothing is changed
         * If provided map contains a claim with null value then that claim will be removed from the header
         *
         * @param headerClaims the values to use as Claims in the token's Header.
         * @return this same Builder instance.
         */
        @NotNull
        public Builder withHeader(@Nullable Map<String, Object> headerClaims) {
            if (headerClaims == null) {
                return this;
            }

            for (Map.Entry<String, Object> entry : headerClaims.entrySet()) {
                if (entry.getValue() == null) {
                    this.headerClaims.remove(entry.getKey());
                } else {
                    this.headerClaims.put(entry.getKey(), entry.getValue());
                }
            }

            return this;
        }

        /**
         * Add a specific Key Id ("kid") claim to the Header.
         * If the {@link Algorithm} used to sign this token was instantiated with a KeyProvider, the 'kid' value will be taken from that provider and this one will be ignored.
         *
         * @param keyId the Key Id value.
         * @return this same Builder instance.
         */
        @NotNull
        public Builder withKeyId(@Nullable String keyId) {
            this.headerClaims.put(PublicClaims.KEY_ID, keyId);
            return this;
        }

        /**
         * Add a specific Issuer ("iss") claim to the Payload.
         *
         * @param issuer the Issuer value.
         * @return this same Builder instance.
         */
        @NotNull
        public Builder withIssuer(@Nullable String issuer) {
            addClaim(PublicClaims.ISSUER, issuer);
            return this;
        }

        /**
         * Add a specific Subject ("sub") claim to the Payload.
         *
         * @param subject the Subject value.
         * @return this same Builder instance.
         */
        @NotNull
        public Builder withSubject(@Nullable String subject) {
            addClaim(PublicClaims.SUBJECT, subject);
            return this;
        }

        /**
         * Add a specific Audience ("aud") claim to the Payload.
         *
         * @param audience the Audience value.
         * @return this same Builder instance.
         */
        @NotNull
        public Builder withAudience(@Nullable String... audience) {
            addClaim(PublicClaims.AUDIENCE, audience);
            return this;
        }

        /**
         * Add a specific Expires At ("exp") claim to the Payload.
         *
         * @param expiresAt the Expires At value.
         * @return this same Builder instance.
         */
        @NotNull
        public Builder withExpiresAt(@Nullable Date expiresAt) {
            addClaim(PublicClaims.EXPIRES_AT, expiresAt);
            return this;
        }

        /**
         * Add a specific Not Before ("nbf") claim to the Payload.
         *
         * @param notBefore the Not Before value.
         * @return this same Builder instance.
         */
        @NotNull
        public Builder withNotBefore(@Nullable Date notBefore) {
            addClaim(PublicClaims.NOT_BEFORE, notBefore);
            return this;
        }

        /**
         * Add a specific Issued At ("iat") claim to the Payload.
         *
         * @param issuedAt the Issued At value.
         * @return this same Builder instance.
         */
        @NotNull
        public Builder withIssuedAt(@Nullable Date issuedAt) {
            addClaim(PublicClaims.ISSUED_AT, issuedAt);
            return this;
        }

        /**
         * Add a specific JWT Id ("jti") claim to the Payload.
         *
         * @param jwtId the Token Id value.
         * @return this same Builder instance.
         */
        @NotNull
        public Builder withJWTId(@Nullable String jwtId) {
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
        @NotNull
        public Builder withClaim(@NotNull String name, @Nullable Boolean value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
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
        @NotNull
        public Builder withClaim(@NotNull String name, @Nullable Integer value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
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
        @NotNull
        public Builder withClaim(@NotNull String name, @Nullable Long value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
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
        @NotNull
        public Builder withClaim(@NotNull String name, @Nullable Double value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
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
        @NotNull
        public Builder withClaim(@NotNull String name, @Nullable String value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
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
        @NotNull
        public Builder withClaim(@NotNull String name, @Nullable Date value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        /**
         * Add a custom Array Claim with the given items.
         *
         * @param name  the Claim's name.
         * @param items the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        @NotNull
        public Builder withArrayClaim(@NotNull String name, @Nullable String[] items) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, items);
            return this;
        }

        /**
         * Add a custom Array Claim with the given items.
         *
         * @param name  the Claim's name.
         * @param items the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        @NotNull
        public Builder withArrayClaim(@NotNull String name, @Nullable Integer[] items) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, items);
            return this;
        }

        /**
         * Add a custom Array Claim with the given items.
         *
         * @param name  the Claim's name.
         * @param items the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null
         */
        @NotNull
        public Builder withArrayClaim(@NotNull String name, @Nullable Long[] items) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, items);
            return this;
        }

        /**
         * Add a custom Map Claim with the given items.
         * <p>
         * Accepted nested types are {@linkplain Map} and {@linkplain List} with basic types
         * {@linkplain Boolean}, {@linkplain Integer}, {@linkplain Long}, {@linkplain Double},
         * {@linkplain String} and {@linkplain Date}. {@linkplain Map}s cannot contain null keys or values.
         * {@linkplain List}s can contain null elements.
         *
         * @param name the Claim's name.
         * @param map  the Claim's key-values.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null, or if the map contents does not validate.
         */
        @NotNull
        public Builder withClaim(@NotNull String name, @Nullable Map<String, ?> map) throws IllegalArgumentException {
            assertNonNull(name);
            // validate map contents
            if (map != null && !validateClaim(map)) {
                throw new IllegalArgumentException("Expected map containing Map, List, Boolean, Integer, Long, Double, String and Date");
            }
            addClaim(name, map);
            return this;
        }

        /**
         * Add a custom List Claim with the given items.
         * <p>
         * Accepted nested types are {@linkplain Map} and {@linkplain List} with basic types
         * {@linkplain Boolean}, {@linkplain Integer}, {@linkplain Long}, {@linkplain Double},
         * {@linkplain String} and {@linkplain Date}. {@linkplain Map}s cannot contain null keys or values.
         * {@linkplain List}s can contain null elements.
         *
         * @param name the Claim's name.
         * @param list the Claim's list of values.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null, or if the list contents does not validate.
         */

        @NotNull
        public Builder withClaim(@NotNull String name, @Nullable List<?> list) throws IllegalArgumentException {
            assertNonNull(name);
            // validate list contents
            if (list != null && !validateClaim(list)) {
                throw new IllegalArgumentException("Expected list containing Map, List, Boolean, Integer, Long, Double, String and Date");
            }
            addClaim(name, list);
            return this;
        }

        private static boolean validateClaim(@NotNull Map<?, ?> map) {
            // do not accept null values in maps
            for (Entry<?, ?> entry : map.entrySet()) {
                Object value = entry.getValue();
                if (value == null || !isSupportedType(value)) {
                    return false;
                }

                if (entry.getKey() == null || !(entry.getKey() instanceof String)) {
                    return false;
                }
            }
            return true;
        }

        private static boolean validateClaim(@NotNull List<?> list) {
            // accept null values in list
            for (Object object : list) {
                if (object != null && !isSupportedType(object)) {
                    return false;
                }
            }
            return true;
        }

        private static boolean isSupportedType(@NotNull Object value) {
            if (value instanceof List) {
                return validateClaim((List<?>) value);
            } else if (value instanceof Map) {
                return validateClaim((Map<?, ?>) value);
            } else {
                return isBasicType(value);
            }
        }

        private static boolean isBasicType(@NotNull Object value) {
            Class<?> c = value.getClass();

            if (c.isArray()) {
                return c == Integer[].class || c == Long[].class || c == String[].class;
            }
            return c == String.class || c == Integer.class || c == Long.class || c == Double.class || c == Date.class || c == Boolean.class;
        }

        /**
         * Creates a new JWT and signs is with the given algorithm
         *
         * @param algorithm used to sign the JWT
         * @return a new JWT token
         * @throws IllegalArgumentException if the provided algorithm is null.
         * @throws JWTCreationException     if the claims could not be converted to a valid JSON or there was a problem with the signing key.
         */
        public String sign(@NotNull Algorithm algorithm) throws IllegalArgumentException, JWTCreationException {
            if (algorithm == null) {
                throw new IllegalArgumentException("The Algorithm cannot be null.");
            }
            headerClaims.put(PublicClaims.ALGORITHM, algorithm.getName());
            if (!headerClaims.containsKey(PublicClaims.TYPE)) {
                headerClaims.put(PublicClaims.TYPE, "JWT");
            }
            String signingKeyId = algorithm.getSigningKeyId();
            if (signingKeyId != null) {
                withKeyId(signingKeyId);
            }
            return new JWTCreator(algorithm, headerClaims, payloadClaims).sign();
        }

        private void assertNonNull(@NotNull String name) {
            if (name == null) {
                throw new IllegalArgumentException("The Custom Claim's name can't be null.");
            }
        }

        private void addClaim(@NotNull String name, @Nullable Object value) {
            if (value == null) {
                payloadClaims.remove(name);
                return;
            }
            payloadClaims.put(name, value);
        }
    }

    private String sign() throws SignatureGenerationException {
        String header = Base64.encodeBase64URLSafeString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = Base64.encodeBase64URLSafeString(payloadJson.getBytes(StandardCharsets.UTF_8));

        byte[] signatureBytes = algorithm.sign(header.getBytes(StandardCharsets.UTF_8), payload.getBytes(StandardCharsets.UTF_8));
        String signature = Base64.encodeBase64URLSafeString((signatureBytes));

        return String.format("%s.%s.%s", header, payload, signature);
    }
}
