package com.auth0.jwtdecodejava;

import com.auth0.jwtdecodejava.exceptions.JWTException;
import com.auth0.jwtdecodejava.impl.JWTParser;
import com.auth0.jwtdecodejava.interfaces.Claim;
import com.auth0.jwtdecodejava.interfaces.Header;
import com.auth0.jwtdecodejava.interfaces.JWT;
import com.auth0.jwtdecodejava.interfaces.Payload;
import com.sun.istack.internal.NotNull;

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
        final String[] parts = splitToken(token);
        final JWTParser converter = new JWTParser();
        header = converter.parseHeader(base64Decode(parts[0]));
        payload = converter.parsePayload(base64Decode(parts[1]));
        signature = parts[2];
    }

    private String[] splitToken(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new JWTException(String.format("The token was expected to have 3 parts, but got %s.", parts.length));
        }
        return parts;
    }

    @Override
    public String getAlgorithm() {
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
    public Claim getClaim(@NotNull String name) {
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
