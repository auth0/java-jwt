package com.auth0.jwt;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * JWT Java Implementation
 * Adapted from https://bitbucket.org/lluisfaja/javajwt/wiki/Home
 * See <a href="https://bitbucket.org/lluisfaja/javajwt/src/3941d23e8e70f681d8a9a2584760e58e79e498f1/JavaJWT/src/com/unblau/javajwt/JWTVerifier.java">JWTVerifier.java</a>
 */
public class JWTVerifier {

    private final byte[] secret;
    private final String audience;
    private final String issuer;
    private final Base64 decoder = new Base64(true);;

    private final ObjectMapper mapper;

    private Map<String, String> algorithms;

    public JWTVerifier(String secret, String audience, String issuer) {
        this(secret.getBytes(StandardCharsets.UTF_8), audience, issuer);
    }

    public JWTVerifier(String secret, String audience) {
        this(secret, audience, null);
    }

    public JWTVerifier(String secret) {
        this(secret, null, null);
    }

    public JWTVerifier(byte[] secret, String audience, String issuer) {
        if (secret == null || secret.length == 0) {
            throw new IllegalArgumentException("Secret cannot be null or empty");
        }

    	mapper = new ObjectMapper();

        algorithms = new HashMap<String, String>();
        algorithms.put("HS256", "HmacSHA256");
        algorithms.put("HS384", "HmacSHA384");
        algorithms.put("HS512", "HmacSHA512");

        this.secret = secret;
        this.audience = audience;
        this.issuer = issuer;
    }

    public JWTVerifier(byte[] secret, String audience) {
        this(secret, audience, null);
    }

    public JWTVerifier(byte[] secret) {
        this(secret, null, null);
    }

    /**
     * Performs JWT validation
     *
     * @param token token to verify
     * @throws SignatureException    when signature is invalid
     * @throws JWTVerifyException    when expiration, issuer or audience are invalid
     * @throws IllegalStateException when token's structure is invalid
     */
    public Map<String, Object> verify(String token)
            throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException,
            IOException, SignatureException, JWTVerifyException {
        if (token == null || "".equals(token)) {
            throw new IllegalStateException("token not set");
        }

        String[] pieces = token.split("\\.");

        // check number of segments
        if (pieces.length != 3) {
            throw new IllegalStateException("Wrong number of segments: " + pieces.length);
        }

        // get JWTHeader JSON object. Extract algorithm
        JsonNode jwtHeader = decodeAndParse(pieces[0]);

        String algorithm = getAlgorithm(jwtHeader);

        // get JWTClaims JSON object
        JsonNode jwtPayload = decodeAndParse(pieces[1]);

        // check signature
        verifySignature(pieces, algorithm);

        // additional JWTClaims checks
        verifyExpiration(jwtPayload);
        verifyIssuer(jwtPayload);
        verifyAudience(jwtPayload);

        return mapper.treeToValue(jwtPayload, Map.class);
    }

    void verifySignature(String[] pieces, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Mac hmac = Mac.getInstance(algorithm);
        hmac.init(new SecretKeySpec(secret, algorithm));
        byte[] sig = hmac.doFinal(new StringBuilder(pieces[0]).append(".").append(pieces[1]).toString().getBytes());

        if (!MessageDigest.isEqual(sig, decoder.decode(pieces[2]))) {
            throw new SignatureException("signature verification failed");
        }
    }

    void verifyExpiration(JsonNode jwtClaims) throws JWTExpiredException {
        final long expiration = jwtClaims.has("exp") ? jwtClaims.get("exp").asLong(0) : 0;

        if (expiration != 0 && System.currentTimeMillis() / 1000L >= expiration) {
            throw new JWTExpiredException("jwt expired", expiration);
        }
    }

    void verifyIssuer(JsonNode jwtClaims) throws JWTIssuerException {
        final String issuerFromToken = jwtClaims.has("iss") ? jwtClaims.get("iss").asText() : null;

        if (issuerFromToken != null && issuer != null && !issuer.equals(issuerFromToken)) {
            throw new JWTIssuerException("jwt issuer invalid", issuerFromToken);
        }
    }

    void verifyAudience(JsonNode jwtClaims) throws JWTAudienceException {
        if (audience == null)
            return;
        JsonNode audNode = jwtClaims.get("aud");
        if (audNode == null)
            return;
        if (audNode.isArray()) {
            for (JsonNode jsonNode : audNode) {
                if (audience.equals(jsonNode.textValue()))
                    return;
            }
        } else if (audNode.isTextual()) {
            if (audience.equals(audNode.textValue()))
                return;
        }
        throw new JWTAudienceException("jwt audience invalid", audNode);
    }

    String getAlgorithm(JsonNode jwtHeader) {
        final String algorithmName = jwtHeader.has("alg") ? jwtHeader.get("alg").asText() : null;

        if (jwtHeader.get("alg") == null) {
            throw new IllegalStateException("algorithm not set");
        }

        if (algorithms.get(algorithmName) == null) {
            throw new IllegalStateException("unsupported algorithm");
        }

        return algorithms.get(algorithmName);
    }

    JsonNode decodeAndParse(String b64String) throws IOException {
        String jsonString = new String(decoder.decode(b64String), StandardCharsets.UTF_8);
        JsonNode jwtHeader = mapper.readValue(jsonString, JsonNode.class);
        return jwtHeader;
    }
}
