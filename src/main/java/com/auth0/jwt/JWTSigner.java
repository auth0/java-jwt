package com.auth0.jwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.*;
import java.util.*;

/**
 * Handles JWT Sign Operation
 *
 * Default algorithm when none provided is HMAC SHA-256 ("HS256")
 *
 * See associated library test cases for clear examples on usage
 *
 */
public class JWTSigner {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private byte[] secret;
    private PrivateKey privateKey;

    // Default algorithm HMAC SHA-256 ("HS256")
    protected final static Algorithm DEFAULT_ALGORITHM = Algorithm.HS256;

    public JWTSigner(final String secret) {
        this(secret.getBytes());
    }

    public JWTSigner(final byte[] secret) {
        Validate.notNull(secret);
        this.secret = secret;
    }

    public JWTSigner(final PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * Generate a JSON Web Token.
     *
     * @param claims  A map of the JWT claims that form the payload. Registered claims
     *                must be of appropriate Java datatype as following:
     *                <ul>
     *                <li>iss, sub: String
     *                <li>exp, nbf, iat, jti: numeric, eg. Long
     *                <li>aud: String, or Collection&lt;String&gt;
     *                </ul>
     *                All claims with a null value are left out the JWT.
     *                Any claims set automatically as specified in
     *                the "options" parameter override claims in this map.
     * @param options Allow choosing the signing algorithm, and automatic setting of some registered claims.
     */
    public String sign(final Map<String, Object> claims, final Options options) {
        Validate.notNull(claims);
        final Algorithm algorithm = (options != null && options.algorithm != null) ? options.algorithm : DEFAULT_ALGORITHM;
        final List<String> segments = new ArrayList<>();
        try {
            segments.add(encodedHeader(algorithm));
            segments.add(encodedPayload(claims, options));
            segments.add(encodedSignature(join(segments, "."), algorithm));
            return join(segments, ".");
        } catch (Exception e) {
            throw new RuntimeException(e.getCause());
        }
    }
    /**
     * Generate a JSON Web Token.
     *
     * @param claims  A map of the JWT claims that form the payload. Registered claims
     *                must be of appropriate Java datatype as following:
     *                <ul>
     *                <li>iss, sub: String
     *                <li>exp, nbf, iat, jti: numeric, eg. Long
     *                <li>aud: String, or Collection&lt;String&gt;
     *                </ul>
     *                All claims with a null value are left out the JWT.
     *                Any claims set automatically as specified in
     *                the "options" parameter override claims in this map.
     * @param options Allow choosing the signing algorithm, and automatic setting of some registered claims.
     * @param header Allow add headers
     */
    public String sign(final Map<String, Object> claims, final Options options,final Map<String,String> header) {
        Validate.notNull(claims);
        final Algorithm algorithm = (options != null && options.algorithm != null) ? options.algorithm : DEFAULT_ALGORITHM;
        final List<String> segments = new ArrayList<>();
        try {
            segments.add(encodedHeader(algorithm,header));
            segments.add(encodedPayload(claims, options));
            segments.add(encodedSignature(join(segments, "."), algorithm));
            return join(segments, ".");
        } catch (Exception e) {
            throw new RuntimeException(e.getCause());
        }
    }

    /**
     * Generate a JSON Web Token using the default algorithm HMAC SHA-256 ("HS256")
     * and no claims automatically set.
     */
    public String sign(final Map<String, Object> claims) {
        Validate.notNull(claims);
        return sign(claims, null);
    }

    /**
     * Generate the header part of a JSON web token.
     */
    private String encodedHeader(final Algorithm algorithm) throws UnsupportedEncodingException {
        Validate.notNull(algorithm);
        // create the header
        final ObjectNode header = JsonNodeFactory.instance.objectNode();
        header.put("typ", "JWT");
        header.put("alg", algorithm.name());
        return base64UrlEncode(header.toString().getBytes("UTF-8"));
    }

    private String encodedHeader(final Algorithm algorithm,Map<String,String> _header) throws UnsupportedEncodingException {
        Validate.notNull(algorithm);
        // create the header
        final ObjectNode header = JsonNodeFactory.instance.objectNode();
        header.put("typ", "JWT");
        header.put("alg", algorithm.name());
        for (Map.Entry<String, String> entry : _header.entrySet()) {
            header.put( entry.getKey() ,  entry.getValue());
        }

        return base64UrlEncode(header.toString().getBytes("UTF-8"));
    }


    /**
     * Generate the JSON web token payload string from the claims.
     *
     * @param options
     */
    private String encodedPayload(final Map<String, Object> _claims, final Options options) throws IOException {
        final Map<String, Object> claims = new HashMap<>(_claims);
        enforceStringOrURI(claims, "iss");
        enforceStringOrURI(claims, "sub");
        enforceStringOrURICollection(claims, "aud");
        enforceIntDate(claims, "exp");
        enforceIntDate(claims, "nbf");
        enforceIntDate(claims, "iat");
        enforceString(claims, "jti");
        if (options != null) {
            processPayloadOptions(claims, options);
        }
        final String payload = new ObjectMapper().writeValueAsString(claims);
        return base64UrlEncode(payload.getBytes("UTF-8"));
    }

    private void processPayloadOptions(final Map<String, Object> claims, final Options options) {
        Validate.notNull(claims);
        Validate.notNull(options);
        final long now = System.currentTimeMillis() / 1000l;
        if (options.expirySeconds != null)
            claims.put("exp", now + options.expirySeconds);
        if (options.notValidBeforeLeeway != null)
            claims.put("nbf", now - options.notValidBeforeLeeway);
        if (options.isIssuedAt())
            claims.put("iat", now);
        if (options.isJwtId())
            claims.put("jti", UUID.randomUUID().toString());
    }

    // consider cleanup
    private void enforceIntDate(final Map<String, Object> claims, final String claimName) {
        Validate.notNull(claims);
        Validate.notNull(claimName);
        final Object value = handleNullValue(claims, claimName);
        if (value == null)
            return;
        if (!(value instanceof Number)) {
            throw new IllegalStateException(String.format("Claim '%s' is invalid: must be an instance of Number", claimName));
        }
        final long longValue = ((Number) value).longValue();
        if (longValue < 0)
            throw new IllegalStateException(String.format("Claim '%s' is invalid: must be non-negative", claimName));
        claims.put(claimName, longValue);
    }

    // consider cleanup
    private void enforceStringOrURICollection(final Map<String, Object> claims, final String claimName) {
        final Object values = handleNullValue(claims, claimName);
        if (values == null)
            return;
        if (values instanceof Collection) {
            @SuppressWarnings({"unchecked"})
            final Iterator<Object> iterator = ((Collection<Object>) values).iterator();
            while (iterator.hasNext()) {
                Object value = iterator.next();
                String error = checkStringOrURI(value);
                if (error != null)
                    throw new IllegalStateException(String.format("Claim 'aud' element is invalid: %s", error));
            }
        } else {
            enforceStringOrURI(claims, "aud");
        }
    }

    // consider cleanup
    private void enforceStringOrURI(final Map<String, Object> claims, final String claimName) {
        final Object value = handleNullValue(claims, claimName);
        if (value == null)
            return;
        final String error = checkStringOrURI(value);
        if (error != null)
            throw new IllegalStateException(String.format("Claim '%s' is invalid: %s", claimName, error));
    }

    // consider cleanup
    private void enforceString(final Map<String, Object> claims, final String claimName) {
        final Object value = handleNullValue(claims, claimName);
        if (value == null)
            return;
        if (!(value instanceof String))
            throw new IllegalStateException(String.format("Claim '%s' is invalid: not a string", claimName));
    }

    // consider cleanup
    private Object handleNullValue(final Map<String, Object> claims, final String claimName) {
        if (!claims.containsKey(claimName))
            return null;
        final Object value = claims.get(claimName);
        if (value == null) {
            claims.remove(claimName);
            return null;
        }
        return value;
    }

    // consider cleanup
    private String checkStringOrURI(final Object value) {
        if (!(value instanceof String))
            return "not a string";
        final String stringOrUri = (String) value;
        if (!stringOrUri.contains(":"))
            return null;
        try {
            new URI(stringOrUri);
        } catch (URISyntaxException e) {
            return "not a valid URI";
        }
        return null;
    }

    /**
     * Sign the header and payload
     */
    private String encodedSignature(final String signingInput, final Algorithm algorithm) throws NoSuchAlgorithmException, InvalidKeyException,
            NoSuchProviderException, SignatureException, JWTAlgorithmException {
        Validate.notNull(signingInput);
        Validate.notNull(algorithm);
        switch (algorithm) {
            case HS256:
            case HS384:
            case HS512:
                return base64UrlEncode(signHmac(algorithm, signingInput, secret));
            case RS256:
            case RS384:
            case RS512:
                return base64UrlEncode(signRs(algorithm, signingInput, privateKey));
            default:
                throw new JWTAlgorithmException("Unsupported signing method");
        }
    }

    /**
     * Safe URL encode a byte array to a String
     */
    private String base64UrlEncode(final byte[] str) {
        Validate.notNull(str);
        return new String(Base64.encodeBase64URLSafe(str));
    }

    /**
     * Sign an input string using HMAC and return the encrypted bytes
     */
    private static byte[] signHmac(final Algorithm algorithm, final String msg, final byte[] secret) throws NoSuchAlgorithmException, InvalidKeyException {
        Validate.notNull(algorithm);
        Validate.notNull(msg);
        Validate.notNull(secret);
        final Mac mac = Mac.getInstance(algorithm.getValue());
        mac.init(new SecretKeySpec(secret, algorithm.getValue()));
        return mac.doFinal(msg.getBytes());
    }

    /**
     * Sign an input string using RSA and return the encrypted bytes
     */
    private static byte[] signRs(final Algorithm algorithm, final String msg, final PrivateKey privateKey) throws NoSuchProviderException,
            NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Validate.notNull(algorithm);
        Validate.notNull(msg);
        Validate.notNull(privateKey);
        final byte[] messageBytes = msg.getBytes();
        final Signature signature = Signature.getInstance(algorithm.getValue(), "BC");
        signature.initSign(privateKey);
        signature.update(messageBytes);
        return signature.sign();
    }

    private String join(final List<String> input, final String separator) {
        Validate.notNull(input);
        Validate.notNull(separator);
        return StringUtils.join(input.iterator(), separator);
    }

    /**
     * An option object for JWT signing operation. Allow choosing the algorithm, and/or specifying
     * claims to be automatically set.
     */
    public static class Options {

        private Algorithm algorithm;
        private Integer expirySeconds;
        private Integer notValidBeforeLeeway;
        private boolean issuedAt;
        private boolean jwtId;

        public Algorithm getAlgorithm() {
            return algorithm;
        }

        /**
         * Algorithm to sign JWT with.
         */
        public Options setAlgorithm(final Algorithm algorithm) {
            this.algorithm = algorithm;
            return this;
        }


        public Integer getExpirySeconds() {
            return expirySeconds;
        }

        /**
         * Set JWT claim "exp" to current timestamp plus this value.
         * Overrides content of <code>claims</code> in <code>sign()</code>.
         */
        public Options setExpirySeconds(final Integer expirySeconds) {
            this.expirySeconds = expirySeconds;
            return this;
        }

        public Integer getNotValidBeforeLeeway() {
            return notValidBeforeLeeway;
        }

        /**
         * Set JWT claim "nbf" to current timestamp minus this value.
         * Overrides content of <code>claims</code> in <code>sign()</code>.
         */
        public Options setNotValidBeforeLeeway(final Integer notValidBeforeLeeway) {
            this.notValidBeforeLeeway = notValidBeforeLeeway;
            return this;
        }

        public boolean isIssuedAt() {
            return issuedAt;
        }

        /**
         * Set JWT claim "iat" to current timestamp. Defaults to false.
         * Overrides content of <code>claims</code> in <code>sign()</code>.
         */
        public Options setIssuedAt(final boolean issuedAt) {
            this.issuedAt = issuedAt;
            return this;
        }

        public boolean isJwtId() {
            return jwtId;
        }

        /**
         * Set JWT claim "jti" to a pseudo random unique value (type 4 UUID). Defaults to false.
         * Overrides content of <code>claims</code> in <code>sign()</code>.
         */
        public Options setJwtId(final boolean jwtId) {
            this.jwtId = jwtId;
            return this;
        }

    }

}
