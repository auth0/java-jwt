package com.auth0.jwt.impl;

import com.auth0.jwt.interfaces.Header;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static com.auth0.jwt.impl.ClaimImpl.extractClaim;
import static com.auth0.jwt.impl.PublicClaims.*;

/**
 * The HeaderImpl class implements the Header interface.
 */
class HeaderImpl implements Header {
    private final Map<String, JsonNode> tree;

    HeaderImpl(Map<String, JsonNode> tree) {
        this.tree = Collections.unmodifiableMap(tree == null ? new HashMap<String, JsonNode>() : tree);
    }

    Map<String, JsonNode> getTree() {
        return tree;
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
