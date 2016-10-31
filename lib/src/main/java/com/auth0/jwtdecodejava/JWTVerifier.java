package com.auth0.jwtdecodejava;

import com.auth0.jwtdecodejava.algorithms.Algorithm;
import com.auth0.jwtdecodejava.algorithms.HSAlgorithm;
import com.auth0.jwtdecodejava.algorithms.NoneAlgorithm;
import com.auth0.jwtdecodejava.algorithms.RSAlgorithm;
import com.auth0.jwtdecodejava.exceptions.AlgorithmMismatchException;
import com.auth0.jwtdecodejava.exceptions.InvalidClaimException;
import com.auth0.jwtdecodejava.exceptions.JWTException;
import com.auth0.jwtdecodejava.exceptions.SignatureVerificationException;
import com.auth0.jwtdecodejava.impl.PublicClaims;
import com.auth0.jwtdecodejava.interfaces.JWT;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.auth0.jwtdecodejava.algorithms.NoneAlgorithm.none;

public class JWTVerifier {
    private final Algorithm algorithm;
    private final String secret;
    private final PublicKey key;
    private final Map<String, Object> claims;

    private JWTVerifier(Algorithm algorithm, String secret, PublicKey key) {
        this.algorithm = algorithm;
        this.key = key;
        this.secret = secret;
        this.claims = new HashMap<>();
    }

    public static JWTVerifier init() throws IllegalArgumentException {
        return init(none, null, null);
    }

    public static JWTVerifier init(HSAlgorithm algorithm, String secret) throws IllegalArgumentException {
        return init(algorithm, null, secret);
    }

    public static JWTVerifier init(RSAlgorithm algorithm, PublicKey publicKey) throws IllegalArgumentException {
        return init(algorithm, publicKey, null);
    }

    private static JWTVerifier init(Algorithm algorithm, PublicKey publicKey, String secret) throws IllegalArgumentException {
        if (algorithm == null) {
            throw new IllegalArgumentException("The Algorithm cannot be null.");
        }
        if (algorithm instanceof HSAlgorithm && secret == null) {
            throw new IllegalArgumentException(String.format("You can't use the %s algorithm without providing a valid Secret.", algorithm.name()));
        }
        if (algorithm instanceof RSAlgorithm && publicKey == null) {
            throw new IllegalArgumentException(String.format("You can't use the %s algorithm without providing a valid PublicKey.", algorithm.name()));
        }
        return new JWTVerifier(algorithm, secret, publicKey);
    }

    public JWTVerifier withIssuer(String issuer) {
        requireClaim(PublicClaims.ISSUER, issuer);
        return this;
    }

    public JWTVerifier withSubject(String subject) {
        requireClaim(PublicClaims.SUBJECT, subject);
        return this;
    }

    public JWTVerifier withAudience(String[] audience) {
        requireClaim(PublicClaims.AUDIENCE, audience);
        return this;
    }

    public JWTVerifier withExpiresAt(Date expiresAt) {
        requireClaim(PublicClaims.EXPIRES_AT, expiresAt);
        return this;
    }

    public JWTVerifier withNotBefore(Date notBefore) {
        requireClaim(PublicClaims.NOT_BEFORE, notBefore);
        return this;
    }

    public JWTVerifier withIssuedAt(Date issuedAt) {
        requireClaim(PublicClaims.ISSUED_AT, issuedAt);
        return this;
    }

    public JWTVerifier withJWTId(String jwtId) {
        requireClaim(PublicClaims.JWT_ID, jwtId);
        return this;
    }

    public JWT verify(String token) throws JWTException {
        JWT jwt = JWTDecoder.decode(token);
        verifyAlgorithm(jwt, algorithm);
        verifySignature(SignUtils.splitToken(token));
        verifyClaims(jwt, claims);
        return jwt;
    }

    private void verifySignature(String[] parts) {
        if (algorithm instanceof HSAlgorithm) {
            try {
                SignUtils.verifyHS((HSAlgorithm) algorithm, parts, secret);
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new SignatureVerificationException(algorithm, e);
            }
        } else if (algorithm instanceof RSAlgorithm) {
            try {
                SignUtils.verifyRS((RSAlgorithm) algorithm, parts, key);
            } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
                throw new SignatureVerificationException(algorithm, e);
            }
        } else if (algorithm instanceof NoneAlgorithm && !parts[2].isEmpty()) {
            throw new SignatureVerificationException(algorithm);
        }
    }

    private void verifyAlgorithm(JWT jwt, Algorithm expectedAlgorithm) throws AlgorithmMismatchException, IllegalArgumentException {
        if (!expectedAlgorithm.equals(jwt.getAlgorithm())) {
            throw new AlgorithmMismatchException("The provided Algorithm doesn't match the one defined in the JWT's Header.");
        }
    }

    private void verifyClaims(JWT jwt, Map<String, Object> claims) {
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            assertValidClaim(jwt, entry.getKey(), entry.getValue());
        }
    }

    private void assertValidClaim(JWT jwt, String claimName, Object expectedValue) {
        boolean isValid;
        if (PublicClaims.AUDIENCE.equals(claimName)) {
            isValid = Arrays.equals(jwt.getAudience(), (String[]) expectedValue);
        } else if (PublicClaims.NOT_BEFORE.equals(claimName) || PublicClaims.EXPIRES_AT.equals(claimName) || PublicClaims.ISSUED_AT.equals(claimName)) {
            Date dateValue = (Date) expectedValue;
            isValid = dateValue.equals(jwt.getClaim(claimName).asDate());
        } else {
            String stringValue = (String) expectedValue;
            isValid = stringValue.equals(jwt.getClaim(claimName).asString());
        }

        if (!isValid) {
            throw new InvalidClaimException(String.format("The Claim '%s' value doesn't match the required one.", claimName));
        }
    }

    private void requireClaim(String name, Object value) {
        if (value == null) {
            claims.remove(name);
            return;
        }
        claims.put(name, value);
    }
}
