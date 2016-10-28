package com.auth0.jwtdecodejava;

import com.auth0.jwtdecodejava.enums.Algorithm;
import com.auth0.jwtdecodejava.exceptions.JWTException;
import com.auth0.jwtdecodejava.impl.JWTParser;
import com.auth0.jwtdecodejava.interfaces.Claim;
import com.auth0.jwtdecodejava.interfaces.Header;
import com.auth0.jwtdecodejava.interfaces.JWT;
import com.auth0.jwtdecodejava.interfaces.Payload;

import java.util.Date;

import static com.auth0.jwtdecodejava.Utils.base64Decode;

public final class JWTDecoder implements JWT {

    private Header header;
    private Payload payload;
    private String signature;

    private JWTDecoder(String jwt) {
        parseToken(jwt);
    }

    public static JWT decode(String jwt) {
        return new JWTDecoder(jwt);
    }

    private void parseToken(String token) throws JWTException {
        final String[] parts = Utils.splitToken(token);
        final JWTParser converter = new JWTParser();
        header = converter.parseHeader(base64Decode(parts[0]));
        payload = converter.parsePayload(base64Decode(parts[1]));
        signature = parts[2];
    }

    @Override
    public Algorithm getAlgorithm() {
        return header.getAlgorithm();
    }

    @Override
    public String getType() {
        return header.getType();
    }

    @Override
    public String getContentType() {
        return header.getContentType();
    }

    @Override
    public String getIssuer() {
        return payload.getIssuer();
    }

    @Override
    public String getSubject() {
        return payload.getSubject();
    }

    @Override
    public String[] getAudience() {
        return payload.getAudience();
    }

    @Override
    public Date getExpiresAt() {
        return payload.getExpiresAt();
    }

    @Override
    public Date getNotBefore() {
        return payload.getNotBefore();
    }

    @Override
    public Date getIssuedAt() {
        return payload.getIssuedAt();
    }

    @Override
    public String getId() {
        return payload.getId();
    }

    @Override
    public Claim getClaim(String name) {
        return payload.getClaim(name);
    }

    @Override
    public String getSignature() {
        return signature;
    }

    @Override
    public boolean isExpired() {
        //TODO: Add advanced validation
        return false;
    }
}
