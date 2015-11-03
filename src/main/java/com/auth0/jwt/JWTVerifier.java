package com.auth0.jwt;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.util.Base64;
import java.util.List;
import org.boon.json.JsonParserAndMapper;
import org.boon.json.JsonParserFactory;

/**
 * JWT Java Implementation
 * Adapted from https://bitbucket.org/lluisfaja/javajwt/wiki/Home
 * See <a href="https://bitbucket.org/lluisfaja/javajwt/src/3941d23e8e70f681d8a9a2584760e58e79e498f1/JavaJWT/src/com/unblau/javajwt/JWTVerifier.java">JWTVerifier.java</a>
 */
public class JWTVerifier {

    private final byte[] secret;
    private final String audience;
    private final String issuer;
    private final Base64.Decoder decoder = Base64.getUrlDecoder();
	private final JsonParserAndMapper fastParser = new JsonParserFactory().createFastParser();

//    private final ObjectMapper mapper;

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

//    	mapper = new ObjectMapper();

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
        Map<String,Object> jwtHeader = decodeAndParse(pieces[0]);

        String algorithm = getAlgorithm(jwtHeader);

        // get JWTClaims JSON object
        Map<String,Object> jwtPayload = decodeAndParse(pieces[1]);

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

        if (!MessageDigest.isEqual(sig, decoder.decode(pieces[2]))) {
            throw new SignatureException("signature verification failed");
        }
    }

    void verifyExpiration(Map<String,Object> jwtClaims) throws JWTExpiredException {
		if ( jwtClaims.containsKey("exp") == false  ) {
			return;
		}
		Object exp = jwtClaims.get("exp");
		final long expiration;
        if ( exp instanceof String ) {
			expiration = Long.parseLong((String)exp);
		} else if ( exp instanceof Number ) {
			expiration = ((Number) exp).longValue();
		} else {
			expiration = 0;
		}
		if (expiration != 0 && System.currentTimeMillis() / 1000L >= expiration) {
            throw new JWTExpiredException("jwt expired", expiration);
        }
    }

    void verifyIssuer(Map<String,Object> jwtClaims) throws JWTIssuerException {
        final String issuerFromToken = jwtClaims.containsKey("iss") ? jwtClaims.get("iss").toString() : null;

        if (issuerFromToken != null && issuer != null && !issuer.equals(issuerFromToken)) {
            throw new JWTIssuerException("jwt issuer invalid", issuerFromToken);
        }
    }

    void verifyAudience(Map<String,Object> jwtClaims) throws JWTAudienceException {
        if (audience == null)
            return;
        Object audNode = jwtClaims.get("aud");
        if (audNode == null)
            return;
		if ( audNode instanceof List) {
			List audList = (List)audNode;
            for (Object audListElem : audList) {
                if (audience.equals(audListElem.toString()))
                    return;
            }
		} else if ( audNode instanceof String) {
            if (audience.equals(audNode.toString()))
                return;			
		}
//        if (audNode.isArray()) {
//            for (JsonNode jsonNode : audNode) {
//                if (audience.equals(jsonNode.textValue()))
//                    return;
//            }
//        } else if (audNode.isTextual()) {
//            if (audience.equals(audNode.textValue()))
//                return;
//        }
        throw new JWTAudienceException("jwt audience invalid", audNode);
    }

    String getAlgorithm(Map<String,Object> jwtHeader) {
        final String algorithmName = jwtHeader.containsKey("alg") ? jwtHeader.get("alg").toString() : null;

        if (algorithmName == null) {
            throw new IllegalStateException("algorithm not set");
        }

        if (algorithms.get(algorithmName) == null) {
            throw new IllegalStateException("unsupported algorithm");
        }

        return algorithms.get(algorithmName);
    }

//    JsonNode decodeAndParse(String b64String) throws IOException {
	Map decodeAndParse(String b64String) throws IOException {
        String jsonString = new String(decoder.decode(b64String), "UTF-8");
		Map<String,Object> jwtHeader = this.fastParser.parseMap(jsonString);
//        JsonNode jwtHeader = mapper.readValue(jsonString, JsonNode.class);
        return jwtHeader;
    }
}
