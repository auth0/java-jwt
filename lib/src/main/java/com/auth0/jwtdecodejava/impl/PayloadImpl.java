package com.auth0.jwtdecodejava.impl;

import com.auth0.jwtdecodejava.interfaces.Claim;
import com.auth0.jwtdecodejava.interfaces.Payload;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.Collections;
import java.util.Date;
import java.util.Map;

import static com.auth0.jwtdecodejava.impl.ClaimImpl.extractClaim;

/**
 * The PayloadImpl class implements the Payload interface.
 */
class PayloadImpl implements Payload {
    private final String issuer;
    private final String subject;
    private final String[] audience;
    private final Date expiresAt;
    private final Date notBefore;
    private final Date issuedAt;
    private final String jwtId;
    private final Map<String, JsonNode> tree;

    PayloadImpl(String issuer, String subject, String[] audience, Date expiresAt, Date notBefore, Date issuedAt, String jwtId, Map<String, JsonNode> tree) {
        this.issuer = issuer;
        this.subject = subject;
        this.audience = audience;
        this.expiresAt = expiresAt;
        this.notBefore = notBefore;
        this.issuedAt = issuedAt;
        this.jwtId = jwtId;
        this.tree = Collections.unmodifiableMap(tree);
    }

    @Override
    public String getIssuer() {
        return issuer;
    }

    @Override
    public String getSubject() {
        return subject;
    }

    @Override
    public String[] getAudience() {
        return audience;
    }

    @Override
    public Date getExpiresAt() {
        return expiresAt;
    }

    @Override
    public Date getNotBefore() {
        return notBefore;
    }

    @Override
    public Date getIssuedAt() {
        return issuedAt;
    }

    @Override
    public String getId() {
        return jwtId;
    }

    @Override
    public Claim getClaim(String name) {
        return extractClaim(name, tree);
    }

}
