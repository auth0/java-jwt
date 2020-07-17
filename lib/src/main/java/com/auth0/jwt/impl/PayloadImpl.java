package com.auth0.jwt.impl;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.Payload;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectReader;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.Serializable;
import java.util.*;

import static com.auth0.jwt.impl.JsonNodeClaim.extractClaim;

/**
 * Decoder of string JSON Web Tokens into their POJO representations.
 *
 * @see Payload
 * <p>
 * This class is thread-safe.
 */
class PayloadImpl implements Payload, Serializable {

    private static final long serialVersionUID = 1659021498824562311L;

    private final String issuer;
    private final String subject;
    private final List<String> audience;
    private final Date expiresAt;
    private final Date notBefore;
    private final Date issuedAt;
    private final String jwtId;
    private final Map<String, JsonNode> tree;
    private final ObjectReader objectReader;

    PayloadImpl(String issuer, String subject, List<String> audience, Date expiresAt, Date notBefore, Date issuedAt, String jwtId, Map<String, JsonNode> tree, ObjectReader objectReader) {
        this.issuer = issuer;
        this.subject = subject;
        this.audience = audience != null ? Collections.unmodifiableList(audience) : null;
        this.expiresAt = expiresAt;
        this.notBefore = notBefore;
        this.issuedAt = issuedAt;
        this.jwtId = jwtId;
        this.tree = tree != null ? Collections.unmodifiableMap(tree) : Collections.<String, JsonNode>emptyMap();
        this.objectReader = objectReader;
    }

    Map<String, JsonNode> getTree() {
        return tree;
    }

    @Nullable
    @Override
    public String getIssuer() {
        return issuer;
    }

    @Nullable
    @Override
    public String getSubject() {
        return subject;
    }

    @Nullable
    @Override
    public List<String> getAudience() {
        return audience;
    }

    @Nullable
    @Override
    public Date getExpiresAt() {
        return expiresAt;
    }

    @Nullable
    @Override
    public Date getNotBefore() {
        return notBefore;
    }

    @Nullable
    @Override
    public Date getIssuedAt() {
        return issuedAt;
    }

    @Nullable
    @Override
    public String getId() {
        return jwtId;
    }

    @NotNull
    @Override
    public Claim getClaim(@NotNull String name) {
        return extractClaim(name, tree, objectReader);
    }

    @NotNull
    @Override
    public Map<String, Claim> getClaims() {
        Map<String, Claim> claims = new HashMap<>(tree.size() * 2);
        for (String name : tree.keySet()) {
            claims.put(name, extractClaim(name, tree, objectReader));
        }
        return Collections.unmodifiableMap(claims);
    }
}
