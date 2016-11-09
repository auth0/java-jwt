package com.auth0.jwt;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.Header;
import com.auth0.jwt.interfaces.JWT;
import com.auth0.jwt.interfaces.Payload;

import java.util.Date;

/**
 * The JWTDecoder class holds the decode method to parse a given Token into it's JWT representation.
 */
final class JWTDecoder implements JWT {

    private Header header;
    private Payload payload;
    private String signature;

    private JWTDecoder(String jwt) throws JWTDecodeException {
        parseToken(jwt);
    }

    /**
     * Decode a given Token into a JWT instance.
     * Note that this method doesn't verify the JWT's signature! Use it only if you trust the issuer of the Token.
     *
     * @param token the String representation of the JWT.
     * @return a decoded JWT.
     * @throws JWTDecodeException if any part of the Token contained an invalid JWT or JSON format.
     */
    static JWT decode(String token) throws JWTDecodeException {
        return new JWTDecoder(token);
    }

    private void parseToken(String token) throws JWTDecodeException {
        final String[] parts = SignUtils.splitToken(token);
        final JWTParser converter = new JWTParser();
        String headerJson;
        String payloadJson;
        try {
            headerJson = SignUtils.toUTF8String(SignUtils.base64Decode(parts[0]));
            payloadJson = SignUtils.toUTF8String(SignUtils.base64Decode(parts[1]));
        } catch (NullPointerException e) {
            throw new JWTDecodeException("The UTF-8 Charset isn't initialized.", e);
        }
        header = converter.parseHeader(headerJson);
        payload = converter.parsePayload(payloadJson);
        signature = parts[2];
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
    public Claim getClaim(String name) {
        return payload.getClaim(name);
    }

    @Override
    public String getSignature() {
        return signature;
    }

}
