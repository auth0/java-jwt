package com.auth0.jwtdecodejava.impl;

import com.auth0.jwtdecodejava.interfaces.Header;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.Map;

import static com.auth0.jwtdecodejava.impl.ClaimImpl.extractClaim;
import static com.auth0.jwtdecodejava.impl.Claims.*;

public class HeaderImpl implements Header {
    private final Map<String, JsonNode> tree;

    public HeaderImpl(Map<String, JsonNode> tree) {
        this.tree = tree;
    }

    @Override
    public String getAlgorithm() {
        return extractClaim(ALGORITHM, tree).asString();
    }

    @Override
    public String getType() {
        return extractClaim(TYPE, tree).asString();
    }

    @Override
    public String getContentType() {
        return extractClaim(CONTENT_TYPE, tree).asString();
    }
}
