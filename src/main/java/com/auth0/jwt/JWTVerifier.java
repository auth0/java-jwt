package com.auth0.jwt;


import jodd.json.JoddJson;
import jodd.json.JsonParser;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.*;

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

    private Map<String, String> algorithms;

    public JWTVerifier(String secret, String audience, String issuer) {
        this(secret.getBytes(Charset.forName("UTF-8")), audience, issuer);
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
        Map<String, Object> jwtHeader = decodeAndParse(pieces[0]);

        String algorithm = getAlgorithm(jwtHeader);

        // get JWTClaims JSON object
        Map<String, Object> jwtPayload = decodeAndParse(pieces[1]);

        // check signature
        verifySignature(pieces, algorithm);

        // additional JWTClaims checks
        verifyExpiration(jwtPayload);
        verifyIssuer(jwtPayload);
        verifyAudience(jwtPayload);

        return jwtPayload;
    }

    void verifySignature(String[] pieces, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Mac hmac = Mac.getInstance(algorithm);
        hmac.init(new SecretKeySpec(secret, algorithm));
        byte[] sig = hmac.doFinal(new StringBuilder(pieces[0]).append(".").append(pieces[1]).toString().getBytes());

        if (!MessageDigest.isEqual(sig, decoder.decodeBase64(pieces[2]))) {
            throw new SignatureException("signature verification failed");
        }
    }

    void verifyExpiration(Map<String, Object> jwtClaims) throws JWTExpiredException {
        long expiration = 0L;
        if (jwtClaims.containsKey("exp")) {
            String expStr = jwtClaims.get("exp").toString();
            try {
                expiration = Long.parseLong(expStr);
            } catch (NumberFormatException ignored) {
            }
        }

        if (expiration != 0 && System.currentTimeMillis() / 1000L >= expiration) {
            throw new JWTExpiredException("jwt expired", expiration);
        }
    }

    void verifyIssuer(Map<String, Object> jwtClaims) throws JWTIssuerException {
        final String issuerFromToken = jwtClaims.containsKey("iss")
                ? jwtClaims.get("iss").toString()
                : null;

        if (issuerFromToken != null && issuer != null && !issuer.equals(issuerFromToken)) {
            throw new JWTIssuerException("jwt issuer invalid", issuerFromToken);
        }
    }

    void verifyAudience(Map<String, Object> jwtClaims) throws JWTAudienceException {
        if (audience == null)
            return;
        Object audNode = jwtClaims.get("aud");
        if (audNode == null)
            return;
        if (audNode instanceof List) {
            List audEntries = (List)audNode;
            for (Object audEntry : audEntries) {
                if (audEntry != null && audience.equals(audEntry.toString()))
                    return;
            }
        } else if (audNode instanceof String) {
            if (audience.equals(audNode))
                return;
        }
        throw new JWTAudienceException("jwt audience invalid", audNode);
    }

    String getAlgorithm(Map<String, Object> jwtHeader) {
        final String algorithmName = jwtHeader.containsKey("alg")
                ? jwtHeader.get("alg").toString()
                : null;

        if (jwtHeader.get("alg") == null) {
            throw new IllegalStateException("algorithm not set");
        }

        if (algorithms.get(algorithmName) == null) {
            throw new IllegalStateException("unsupported algorithm");
        }

        return algorithms.get(algorithmName);
    }

    Map<String, Object> decodeAndParse(String b64String) throws IOException {
        String jsonString = new String(decoder.decodeBase64(b64String), "UTF-8");
        return new JsonParser().parse(jsonString);
    }
}
