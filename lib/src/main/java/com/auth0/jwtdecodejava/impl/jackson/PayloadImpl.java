package com.auth0.jwtdecodejava.impl.jackson;

import com.auth0.jwtdecodejava.MissingClaim;
import com.auth0.jwtdecodejava.interfaces.Claim;
import com.auth0.jwtdecodejava.interfaces.Payload;
import com.fasterxml.jackson.databind.JsonNode;
import com.sun.istack.internal.NotNull;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.auth0.jwtdecodejava.impl.PublicClaims.*;

public class PayloadImpl implements Payload {
    private Map<String, Claim> extraClaims;
    private Map<String, Claim> publicClaims;

    public PayloadImpl(Map<String, JsonNode> payloadTree) {
        publicClaims = parsePublicClaims(payloadTree);
        extraClaims = parseExtraClaims(payloadTree);
    }

    private Map<String, Claim> parsePublicClaims(Map<String, JsonNode> tree) {
        Map<String, Claim> map = new HashMap<>();
        map.put(ISSUER, extractClaim(ISSUER, tree));
        map.put(SUBJECT, extractClaim(SUBJECT, tree));
        map.put(EXPIRES_AT, extractClaim(EXPIRES_AT, tree));
        map.put(NOT_BEFORE, extractClaim(NOT_BEFORE, tree));
        map.put(ISSUED_AT, extractClaim(ISSUED_AT, tree));
        map.put(JWT_ID, extractClaim(JWT_ID, tree));
        map.put(AUDIENCE, extractClaim(AUDIENCE, tree));
        return map;
    }

    private Map<String, Claim> parseExtraClaims(Map<String, JsonNode> tree) {
        Map<String, Claim> map = new HashMap<>();
        for (Map.Entry<String, JsonNode> e : tree.entrySet()) {
            map.put(e.getKey(), claimFromNode(e.getKey(), e.getValue()));
        }
        return map;
    }

    @Override
    public String getIssuer() {
        return publicClaims.get(ISSUER).asString();
    }

    @Override
    public String getSubject() {
        return publicClaims.get(SUBJECT).asString();
    }

    @Override
    public String[] getAudience() {
        try {
            return publicClaims.get(AUDIENCE).asArray(String.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public Date getExpiresAt() {
        return publicClaims.get(EXPIRES_AT).asDate();
    }

    @Override
    public Date getNotBefore() {
        return publicClaims.get(NOT_BEFORE).asDate();
    }

    @Override
    public Date getIssuedAt() {
        return publicClaims.get(ISSUED_AT).asDate();
    }

    @Override
    public String getId() {
        return publicClaims.get(JWT_ID).asString();
    }

    @Override
    public Claim getClaim(@NotNull String name) {
        return extraClaims.get(name);
    }


    @NotNull
    private Claim extractClaim(@NotNull String claimName, @NotNull Map<String, JsonNode> tree) {
        JsonNode node = tree.remove(claimName);
        return claimFromNode(claimName, node);
    }

    @NotNull
    private Claim claimFromNode(String claimName, JsonNode node) {
        if (node == null || node.isMissingNode()) {
            return new MissingClaim(claimName);
        }
        return new ClaimImpl(claimName, node);
    }
}
