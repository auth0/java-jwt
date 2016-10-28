package com.auth0.jwtdecodejava.impl;

import com.auth0.jwtdecodejava.JWTDecoder;
import com.auth0.jwtdecodejava.Utils;
import com.auth0.jwtdecodejava.enums.Algorithm;
import com.auth0.jwtdecodejava.exceptions.AlgorithmMismatchException;
import com.auth0.jwtdecodejava.exceptions.InvalidClaimException;
import com.auth0.jwtdecodejava.exceptions.JWTException;
import com.auth0.jwtdecodejava.exceptions.SignatureVerificationException;
import com.auth0.jwtdecodejava.interfaces.JWT;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JWTVerifier {
    private final Algorithm algorithm;
    private final String secret;
    private final Map<String, Object> claims;

    private JWTVerifier(Algorithm algorithm, String secret) {
        this.algorithm = algorithm;
        this.secret = secret;
        this.claims = new HashMap<>();
    }

    public static JWTVerifier init(Algorithm algorithm, String secret) throws IllegalArgumentException {
        if (algorithm == null) {
            throw new IllegalArgumentException("The Algorithm cannot be null.");
        }
        switch (algorithm) {
            case HS256:
            case HS384:
            case HS512:
                if (secret == null) {
                    throw new IllegalArgumentException(String.format("You can't use the %s algorithm without providing a valid Secret.", algorithm.name()));
                }
                break;
            default:
        }
        return new JWTVerifier(algorithm, secret);
    }

    public JWTVerifier withIssuer(String issuer) {
        requireClaim(Claims.ISSUER, issuer);
        return this;
    }

    public JWTVerifier withSubject(String subject) {
        requireClaim(Claims.SUBJECT, subject);
        return this;
    }

    public JWTVerifier withAudience(String[] audience) {
        requireClaim(Claims.AUDIENCE, audience);
        return this;
    }

    public JWTVerifier withExpiresAt(Date expiresAt) {
        requireClaim(Claims.EXPIRES_AT, expiresAt);
        return this;
    }

    public JWTVerifier withNotBefore(Date notBefore) {
        requireClaim(Claims.NOT_BEFORE, notBefore);
        return this;
    }

    public JWTVerifier withIssuedAt(Date issuedAt) {
        requireClaim(Claims.ISSUED_AT, issuedAt);
        return this;
    }

    public JWTVerifier withJWTId(String jwtId) {
        requireClaim(Claims.JWT_ID, jwtId);
        return this;
    }

    public JWT verify(String token) throws JWTException {
        JWT jwt = JWTDecoder.decode(token);
        verifyClaims(jwt, claims);
        verifyAlgorithm(jwt, algorithm);
        verifySignature(Utils.splitToken(token));
        return jwt;
    }

    private void verifySignature(String[] parts) {
        switch (algorithm) {
            case HS256:
            case HS384:
            case HS512:
                try {
                    Utils.verifyHS(parts, secret, algorithm);
                } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                    throw new SignatureVerificationException(algorithm, e);
                }
                break;
            default:
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
        if (Claims.AUDIENCE.equals(claimName)) {
            isValid = Arrays.equals(jwt.getAudience(), (String[]) expectedValue);
        } else if (Claims.NOT_BEFORE.equals(claimName) || Claims.EXPIRES_AT.equals(claimName) || Claims.ISSUED_AT.equals(claimName)) {
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
