package com.auth0.jwt.impl;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.Header;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;

import java.io.Serializable;
import java.util.Collections;
import java.util.Map;

import static com.auth0.jwt.impl.JsonNodeClaim.extractClaim;

/**
 * The BasicHeader class implements the Header interface.
 */
class BasicHeader implements Header, Serializable {
    private static final long serialVersionUID = -4659137688548605095L;

    private final String algorithm;
    private final String type;
    private final String contentType;
    private final String keyId;
    private final Map<String, JsonNode> tree;
    private final DeserializationContext context;

    BasicHeader(
            String algorithm,
            String type,
            String contentType,
            String keyId,
            Map<String, JsonNode> tree,
            DeserializationContext context
    ) {
        this.algorithm = algorithm;
        this.type = type;
        this.contentType = contentType;
        this.keyId = keyId;
        this.tree = tree == null ? Collections.emptyMap() : Collections.unmodifiableMap(tree);
        this.context = context;
    }

    Map<String, JsonNode> getTree() {
        return tree;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getType() {
        return type;
    }

    @Override
    public String getContentType() {
        return contentType;
    }

    @Override
    public String getKeyId() {
        return keyId;
    }

    @Override
    public Claim getHeaderClaim(String name) {
        return extractClaim(name, tree, context);
    }
}
