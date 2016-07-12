package com.auth0.jwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
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
    private final Base64 decoder = new Base64(true);

    private final ObjectMapper mapper;


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
        mapper = new ObjectMapper();
        this.secret = secret;
        this.audience = audience;
        this.issuer = issuer;
    }

    public JWTVerifier(final PublicKey publicKey, final String audience, final String issuer) {
        Validate.notNull(publicKey);
        mapper = new ObjectMapper();
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
    public Map<String, Object> verify(final String token) throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException,
            IOException, SignatureException, JWTVerifyException, JWTAlgorithmException {
        if (token == null || "".equals(token)) {
            throw new IllegalStateException("token not set");
        }
        final String[] pieces = token.split("\\.");
        if (pieces.length != 3) {
            throw new IllegalStateException("Wrong number of segments: " + pieces.length);
        }
        final JsonNode jwtHeader = decodeAndParse(pieces[0]);
        final Algorithm algorithm = getAlgorithm(jwtHeader);
        final JsonNode jwtPayload = decodeAndParse(pieces[1]);
        verifySignature(pieces, algorithm);
        verifyExpiration(jwtPayload);
        verifyIssuer(jwtPayload);
        verifyAudience(jwtPayload);
        return mapper.treeToValue(jwtPayload, Map.class);
    }

    protected void verifySignature(final String[] pieces, final Algorithm algorithm) throws NoSuchAlgorithmException,
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

    void verifyHmac(final Algorithm algorithm, final String[] pieces, final byte[] secret) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        if (secret == null || secret.length == 0) {
            throw new IllegalStateException("Secret cannot be null or empty when using algorithm: " + algorithm.getValue());
        }
        final Mac hmac = Mac.getInstance(algorithm.getValue());
        hmac.init(new SecretKeySpec(secret, algorithm.getValue()));
        final byte[] sig = hmac.doFinal(new StringBuilder(pieces[0]).append(".").append(pieces[1]).toString().getBytes());
        if (!MessageDigest.isEqual(sig, decoder.decode(pieces[2]))) {
            throw new SignatureException("signature verification failed");
        }
    }

    void verifyRs(final Algorithm algorithm, final String[] pieces, final PublicKey publicKey) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, JWTAlgorithmException {
        if (publicKey == null) {
            throw new IllegalStateException("PublicKey cannot be null when using algorithm: " + algorithm.getValue());
        }
        final byte[] decodedSignatureBytes = new Base64(true).decode(pieces[2]);
        final byte[] headerPayloadBytes = new StringBuilder(pieces[0]).append(".").append(pieces[1]).toString().getBytes();
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

    protected void verifyExpiration(final JsonNode jwtClaims) throws JWTExpiredException {
        Validate.notNull(jwtClaims);
        final long expiration = jwtClaims.has("exp") ? jwtClaims.get("exp").asLong(0) : 0;
        if (expiration != 0 && System.currentTimeMillis() / 1000L >= expiration) {
            throw new JWTExpiredException("jwt expired", expiration);
        }
    }

    protected void verifyIssuer(final JsonNode jwtClaims) throws JWTIssuerException {
        Validate.notNull(jwtClaims);

        if (this.issuer == null ) {
            return;
        }

        final String issuerFromToken = jwtClaims.has("iss") ? jwtClaims.get("iss").asText() : null;

        if (issuerFromToken == null || !issuer.equals(issuerFromToken)) {
            throw new JWTIssuerException("jwt issuer invalid", issuerFromToken);
        }
    }

    protected void verifyAudience(final JsonNode jwtClaims) throws JWTAudienceException {
        Validate.notNull(jwtClaims);
        if (audience == null) {
            return;
        }
        final JsonNode audNode = jwtClaims.get("aud");
        if (audNode == null) {
            throw new JWTAudienceException("jwt audience invalid", null);
        }
        if (audNode.isArray()) {
            for (final JsonNode jsonNode : audNode) {
                if (audience.equals(jsonNode.textValue())) {
                    return;
                }
            }
        } else if (audNode.isTextual()) {
            if (audience.equals(audNode.textValue())) {
                return;
            }
        }
        throw new JWTAudienceException("jwt audience invalid", audNode);
    }

    protected Algorithm getAlgorithm(final JsonNode jwtHeader) throws JWTAlgorithmException {
        Validate.notNull(jwtHeader);
        final String algorithmName = jwtHeader.has("alg") ? jwtHeader.get("alg").asText() : null;
        if (jwtHeader.get("alg") == null) {
            throw new IllegalStateException("algorithm not set");
        }
        return Algorithm.findByName(algorithmName);
    }

    protected JsonNode decodeAndParse(final String b64String) throws IOException {
        Validate.notNull(b64String);
        final String jsonString = new String(decoder.decode(b64String), "UTF-8");
        final JsonNode jwtHeader = mapper.readValue(jsonString, JsonNode.class);
        return jwtHeader;
    }

}
