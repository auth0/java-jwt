package com.auth0.jwt;

import org.apache.commons.lang3.Validate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.List;
import org.boon.json.JsonParserAndMapper;
import org.boon.json.JsonParserFactory;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.*;
import java.util.Map;

/**
 * Handles JWT Verification Operations
 *
 * Validates claims and signature
 *
 * See associated library test cases for clear examples on usage
 *
 */
public class JWTVerifier {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private byte[] secret;
    private PublicKey publicKey;
    private final String audience;
    private final String issuer;
    private final Base64.Decoder decoder = Base64.getUrlDecoder();
	private final JsonParserAndMapper fastParser = new JsonParserFactory().createFastParser();



    public JWTVerifier(final String secret, final String audience, final String issuer) {
        this(secret.getBytes(Charset.forName("UTF-8")), audience, issuer);
    }

    public JWTVerifier(final String secret, final String audience) {
        this(secret, audience, null);
    }

    public JWTVerifier(final String secret) {
        this(secret, null, null);
    }

    public JWTVerifier(final byte[] secret, final String audience) {
        this(secret, audience, null);
    }

    public JWTVerifier(final byte[] secret) {
        this(secret, null, null);
    }

    public JWTVerifier(final byte[] secret, final String audience, final String issuer) {
        if (secret == null || secret.length == 0) {
            throw new IllegalArgumentException("Secret cannot be null or empty");
        }
        this.secret = secret;
        this.audience = audience;
        this.issuer = issuer;
    }

    public JWTVerifier(final PublicKey publicKey, final String audience, final String issuer) {
        Validate.notNull(publicKey);
        this.publicKey = publicKey;
        this.audience = audience;
        this.issuer = issuer;
    }

    public JWTVerifier(final PublicKey publicKey, final String audience) {
        this(publicKey, audience, null);
    }

    public JWTVerifier(final PublicKey publicKey) {
        this(publicKey, null, null);
    }


    /**
     * Performs JWT validation
     *
     * @param token token to verify
     * @throws SignatureException    when signature is invalid
     * @throws JWTVerifyException    when expiration, issuer or audience are invalid
     * @throws JWTAlgorithmException when the algorithm is missing or unsupported
     * @throws IllegalStateException when token's structure is invalid or secret / public key does not match algorithm of token
     */
    @SuppressWarnings("WeakerAccess")
    public Map<String, Object> verify(final String token) throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException,
            IOException, SignatureException, JWTVerifyException {
        if (token == null || "".equals(token)) {
            throw new IllegalStateException("token not set");
        }
        final String[] pieces = token.split("\\.");
        if (pieces.length != 3) {
            throw new IllegalStateException("Wrong number of segments: " + pieces.length);
        }
        // get JWTHeader JSON object. Extract algorithm
        Map<String,Object> jwtHeader = decodeAndParse(pieces[0]);

        Algorithm algorithm = getAlgorithm(jwtHeader);

        // get JWTClaims JSON object
        Map<String,Object> jwtPayload = decodeAndParse(pieces[1]);

        verifySignature(pieces, algorithm);
        verifyExpiration(jwtPayload);
        verifyIssuer(jwtPayload);
        verifyAudience(jwtPayload);
        return jwtPayload;
    }

    void verifySignature(final String[] pieces, final Algorithm algorithm) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException, JWTAlgorithmException, IllegalStateException {
        Validate.notNull(pieces);
        Validate.notNull(algorithm);
        if (pieces.length != 3) {
            throw new IllegalStateException("Wrong number of segments: " + pieces.length);
        }
        switch (algorithm) {
            case HS256:
            case HS384:
            case HS512:
                verifyHmac(algorithm, pieces, secret);
                return;
            case RS256:
            case RS384:
            case RS512:
                verifyRs(algorithm, pieces, publicKey);
                return;
            default:
                throw new JWTAlgorithmException("Unsupported signing method");
        }
    }

    private void verifyHmac(final Algorithm algorithm, final String[] pieces, final byte[] secret) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        if (secret == null || secret.length == 0) {
            throw new IllegalStateException("Secret cannot be null or empty when using algorithm: " + algorithm.getValue());
        }
        final Mac hmac = Mac.getInstance(algorithm.getValue());
        hmac.init(new SecretKeySpec(secret, algorithm.getValue()));
        final byte[] sig = hmac.doFinal((pieces[0] + "." + pieces[1]).getBytes());
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

    private void verifyRs(final Algorithm algorithm, final String[] pieces, final PublicKey publicKey) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, JWTAlgorithmException {
        if (publicKey == null) {
            throw new IllegalStateException("PublicKey cannot be null when using algorithm: " + algorithm.getValue());
        }
        final byte[] decodedSignatureBytes = decoder.decode(pieces[2]);
        final byte[] headerPayloadBytes = (pieces[0] + "." + pieces[1]).getBytes();
        final boolean verified = verifySignatureWithPublicKey(this.publicKey, headerPayloadBytes, decodedSignatureBytes, algorithm);
        if (!verified) {
            throw new SignatureException("signature verification failed");
        }
    }

    private boolean verifySignatureWithPublicKey(final PublicKey publicKey, final byte[] messageBytes, final byte[] signatureBytes, final Algorithm algorithm) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, JWTAlgorithmException {
        Validate.notNull(publicKey);
        Validate.notNull(messageBytes);
        Validate.notNull(signatureBytes);
        Validate.notNull(algorithm);
        try {
            final Signature signature = Signature.getInstance(algorithm.getValue(), "BC");
            signature.initVerify(publicKey);
            signature.update(messageBytes);
            return signature.verify(signatureBytes);
        } catch (NoSuchProviderException e) {
            throw new JWTAlgorithmException(e.getMessage(), e.getCause());
        }
    }

 
    void verifyIssuer(Map<String,Object> jwtClaims) throws JWTIssuerException {
        Validate.notNull(jwtClaims);

        if (this.issuer == null ) {
            return;
        }
        final String issuerFromToken = jwtClaims.containsKey("iss") ? jwtClaims.get("iss").toString() : null;

        if (issuerFromToken == null || !issuer.equals(issuerFromToken)) {
            throw new JWTIssuerException("jwt issuer invalid", issuerFromToken);
        }
    }

    void verifyAudience(Map<String,Object> jwtClaims) throws JWTAudienceException {
        Validate.notNull(jwtClaims);
        if (audience == null)
            return;
        Object audNode = jwtClaims.get("aud");
        if (audNode == null)
            throw new JWTAudienceException("jwt audience invalid", null);
		if ( audNode instanceof List) {
			List audList = (List)audNode;
            for (Object audListElem : audList) {
                if (audience.equals(audListElem.toString())) {
                    return;
                }
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

    Algorithm getAlgorithm(Map<String,Object> jwtHeader) throws JWTAlgorithmException {
        Validate.notNull(jwtHeader);
        final String algorithmName = jwtHeader.containsKey("alg") ? jwtHeader.get("alg").toString() : null;

        if (algorithmName == null) {
            throw new IllegalStateException("algorithm not set");
        }
        return Algorithm.findByName(algorithmName);
    }

//    JsonNode decodeAndParse(String b64String) throws IOException {
	Map decodeAndParse(String b64String) throws IOException {
        String jsonString = new String(decoder.decode(b64String), "UTF-8");
		Map<String,Object> jwtHeader = this.fastParser.parseMap(jsonString);
//        JsonNode jwtHeader = mapper.readValue(jsonString, JsonNode.class);
        return jwtHeader;
    }

}
