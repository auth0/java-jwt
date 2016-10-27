package com.auth0.jwtdecodejava.impl;

import com.auth0.jwtdecodejava.JWTDecoder;
import com.auth0.jwtdecodejava.exceptions.InvalidClaimException;
import com.auth0.jwtdecodejava.exceptions.JWTException;
import com.auth0.jwtdecodejava.interfaces.JWT;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JWTVerifier {
    private final Map<String, Object> claims;

    private JWTVerifier() {
        this.claims = new HashMap<>();
    }

    public static JWTVerifier init(){
        return new JWTVerifier();
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

    public JWT verify(String jwt) throws JWTException{
        JWT decode = JWTDecoder.decode(jwt);
        verifyClaims(decode, claims);
        return decode;
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
