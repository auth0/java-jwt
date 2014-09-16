package com.auth0.jwt;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.OperationNotSupportedException;

import org.apache.commons.codec.binary.Base64;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * JwtSigner implementation based on the Ruby implementation from http://jwt.io
 * No support for RSA encryption at present
 */
public class JWTSigner {
    private final String secret;
    
    public JWTSigner(String secret) {
        this.secret = secret;
    }

    /**
     * Generate a JSON Web Token.
     *  using the default algorithm HMAC SHA-256 ("HS256")
     * and no claims automatically set.
     * 
     * @param claims A map of the JWT claims that form the payload. Registered claims
     *               must be of appropriate Java datatype as following:
     *               <ul>
     *                  <li>iss, sub: String
     *                  <li>exp, nbf, iat, jti: numeric, eg. Long
     *                  <li>aud: String, or Collection&lt;String&gt;
     *               </ul>
     *               All claims with a null value are left out the JWT.
     *               Any claims set automatically as specified in
     *               the "options" parameter override claims in this map.
     *               
     * @param secret Key to use in signing. Used as-is without Base64 encoding.
     * 
     * @param options Allow choosing the signing algorithm, and automatic setting of some registered claims.
     */
    public String sign(Map<String, Object> claims, Options options) {
        Algorithm algorithm = Algorithm.HS256;
        if (options != null && options.algorithm != null)
            algorithm = options.algorithm;

        List<String> segments = new ArrayList<String>();
        try {
            segments.add(encodedHeader(algorithm));
            segments.add(encodedPayload(claims, options));
            segments.add(encodedSignature(join(segments, "."), algorithm));
        } catch (Exception e) {
            throw (e instanceof RuntimeException) ? (RuntimeException) e : new RuntimeException(e);
        }

        return join(segments, ".");
    }

    /**
     * Generate a JSON Web Token using the default algorithm HMAC SHA-256 ("HS256")
     * and no claims automatically set.
     *
     * @param secret Key to use in signing. Used as-is without Base64 encoding.
     * 
     * For details, see the two parameter variant of this method.
     */
    public String sign(Map<String, Object> claims) {
        return sign(claims, null);
    }
    
    /**
     * Generate the header part of a JSON web token.
     */
    private String encodedHeader(Algorithm algorithm) throws UnsupportedEncodingException {
        if (algorithm == null) { // default the algorithm if not specified
            algorithm = Algorithm.HS256;
        }

        // create the header
        ObjectNode header = JsonNodeFactory.instance.objectNode();
        header.put("type", "JWT");
        header.put("alg", algorithm.name());

        return base64UrlEncode(header.toString().getBytes("UTF-8"));
    }

    /**
     * Generate the JSON web token payload string from the claims.
     * @param options 
     */
    private String encodedPayload(Map<String, Object> _claims, Options options) throws Exception {
        Map<String, Object> claims = new HashMap<String, Object>(_claims);
        enforceStringOrURI(claims, "iss");
        enforceStringOrURI(claims, "sub");
        enforceStringOrURICollection(claims, "aud");
        enforceIntDate(claims, "exp");
        enforceIntDate(claims, "nbf");
        enforceIntDate(claims, "iat");
        enforceString(claims, "jti");
        
        if (options != null)
            processPayloadOptions(claims, options);

        String payload = new ObjectMapper().writeValueAsString(claims);
        return base64UrlEncode(payload.getBytes("UTF-8"));
    }
    
    private void processPayloadOptions(Map<String, Object> claims, Options options) {
        long now = System.currentTimeMillis() / 1000l;
        if (options.expirySeconds != null)
            claims.put("exp", now + options.expirySeconds);
        if (options.notValidBeforeLeeway != null)
            claims.put("nbf", now - options.notValidBeforeLeeway);
        if (options.isIssuedAt())
            claims.put("iat", now);
        if (options.isJwtId())
            claims.put("jti", UUID.randomUUID().toString());
    }

    private void enforceIntDate(Map<String, Object> claims, String claimName) {
        Object value = handleNullValue(claims, claimName);
        if (value == null)
            return;
        if (!(value instanceof Number)) {
            throw new RuntimeException(String.format("Claim '%s' is invalid: must be an instance of Number", claimName));
        }
        long longValue = ((Number) value).longValue();
        if (longValue < 0)
            throw new RuntimeException(String.format("Claim '%s' is invalid: must be non-negative", claimName));
        claims.put(claimName, longValue);
    }

    private void enforceStringOrURICollection(Map<String, Object> claims, String claimName) {
        Object values = handleNullValue(claims, claimName);
        if (values == null)
            return;
        if (values instanceof Collection) {
            @SuppressWarnings({ "unchecked" })
            Iterator<Object> iterator = ((Collection<Object>) values).iterator();
            while (iterator.hasNext()) {
                Object value = iterator.next();
                String error = checkStringOrURI(value);
                if (error != null)
                    throw new RuntimeException(String.format("Claim 'aud' element is invalid: %s", error));
            }
        } else {
            enforceStringOrURI(claims, "aud");
        }
    }

    private void enforceStringOrURI(Map<String, Object> claims, String claimName) {
        Object value = handleNullValue(claims, claimName);
        if (value == null)
            return;
        String error = checkStringOrURI(value);
        if (error != null)
            throw new RuntimeException(String.format("Claim '%s' is invalid: %s", claimName, error));
    }

    private void enforceString(Map<String, Object> claims, String claimName) {
        Object value = handleNullValue(claims, claimName);
        if (value == null)
            return;
        if (!(value instanceof String))
            throw new RuntimeException(String.format("Claim '%s' is invalid: not a string", claimName));
    }

    private Object handleNullValue(Map<String, Object> claims, String claimName) {
        if (! claims.containsKey(claimName))
            return null;
        Object value = claims.get(claimName);
        if (value == null) {
            claims.remove(claimName);
            return null;
        }
        return value;
    }

    private String checkStringOrURI(Object value) {
        if (!(value instanceof String))
            return "not a string";
        String stringOrUri = (String) value;
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
    private String encodedSignature(String signingInput, Algorithm algorithm) throws Exception {
        byte[] signature = sign(algorithm, signingInput, secret);
        return base64UrlEncode(signature);
    }

    /**
     * Safe URL encode a byte array to a String
     */
    private String base64UrlEncode(byte[] str) {
        return new String(Base64.encodeBase64URLSafe(str));
    }

    /**
     * Switch the signing algorithm based on input, RSA not supported
     */
    private static byte[] sign(Algorithm algorithm, String msg, String secret) throws Exception {
        switch (algorithm) {
        case HS256:
        case HS384:
        case HS512:
            return signHmac(algorithm, msg, secret);
        case RS256:
        case RS384:
        case RS512:
        default:
            throw new OperationNotSupportedException("Unsupported signing method");
        }
    }

    /**
     * Sign an input string using HMAC and return the encrypted bytes
     */
    private static byte[] signHmac(Algorithm algorithm, String msg, String secret) throws Exception {
        Mac mac = Mac.getInstance(algorithm.getValue());
        mac.init(new SecretKeySpec(secret.getBytes(), algorithm.getValue()));
        return mac.doFinal(msg.getBytes());
    }

    private String join(List<String> input, String on) {
        int size = input.size();
        int count = 1;
        StringBuilder joined = new StringBuilder();
        for (String string : input) {
            joined.append(string);
            if (count < size) {
                joined.append(on);
            }
            count++;
        }

        return joined.toString();
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
         * Algorithm to sign JWT with. Default is <code>HS256</code>.
         */
        public Options setAlgorithm(Algorithm algorithm) {
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
        public Options setExpirySeconds(Integer expirySeconds) {
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
        public Options setNotValidBeforeLeeway(Integer notValidBeforeLeeway) {
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
        public Options setIssuedAt(boolean issuedAt) {
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
        public Options setJwtId(boolean jwtId) {
            this.jwtId = jwtId;
            return this;
        }
    }
}
