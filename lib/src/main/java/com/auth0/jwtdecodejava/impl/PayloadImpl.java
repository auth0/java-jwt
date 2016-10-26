package com.auth0.jwtdecodejava.impl;

import com.auth0.jwtdecodejava.exceptions.JWTException;
import com.auth0.jwtdecodejava.interfaces.Claim;
import com.auth0.jwtdecodejava.interfaces.Payload;
import com.fasterxml.jackson.databind.JsonNode;
import com.sun.istack.internal.NotNull;

import java.util.Date;
import java.util.Map;

import static com.auth0.jwtdecodejava.impl.ClaimImpl.claimFromNode;
import static com.auth0.jwtdecodejava.impl.ClaimImpl.extractClaim;
import static com.auth0.jwtdecodejava.impl.Claims.*;

class PayloadImpl implements Payload {
    private Map<String, JsonNode> tree;

    PayloadImpl(Map<String, JsonNode> tree) {
        this.tree = tree;
    }

    @Override
    public String getIssuer() {
        return extractClaim(ISSUER, tree).asString();
    }

    @Override
    public String getSubject() {
        return extractClaim(SUBJECT, tree).asString();
    }

    @Override
    public String[] getAudience() {
        JsonNode audNode = tree.get(AUDIENCE);
        if (audNode == null || audNode.isNull()) {
            return new String[]{};
        }
        if (audNode.isTextual() && !audNode.asText().isEmpty()) {
            return new String[]{audNode.asText()};
        }
        Claim claim = claimFromNode(audNode);
        try {
            return claim.asArray(String.class);
        } catch (Exception e) {
            e.printStackTrace();
            throw new JWTException("The Audience contained invalid values.", e);
        }
    }

    @Override
    public Date getExpiresAt() {
        return extractClaim(EXPIRES_AT, tree).asDate();
    }

    @Override
    public Date getNotBefore() {
        return extractClaim(NOT_BEFORE, tree).asDate();
    }

    @Override
    public Date getIssuedAt() {
        return extractClaim(ISSUED_AT, tree).asDate();
    }

    @Override
    public String getId() {
        return extractClaim(JWT_ID, tree).asString();
    }

    @Override
    public Claim getClaim(@NotNull String name) {
        return extractClaim(name, tree);
    }

}
