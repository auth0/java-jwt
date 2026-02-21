package com.auth0.jwt.impl;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.Payload;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;

import java.io.Serializable;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.auth0.jwt.impl.JsonNodeClaim.extractClaim;

/**
 * Decoder of string JSON Web Tokens into their POJO representations.
 * <p>
 * This class is thread-safe.
 *
 * @see Payload
 */
class PayloadImpl implements Payload, Serializable {

    private static final long serialVersionUID = 1659021498824562311L;

    private final String issuer;
    private final String subject;
    private final List<String> audience;
    private final Instant expiresAt;
    private final Instant notBefore;
    private final Instant issuedAt;
    private final String jwtId;
    private final Map<String, JsonNode> tree;
    private final DeserializationContext context;

    PayloadImpl(
            String issuer,
            String subject,
            List<String> audience,
            Instant expiresAt,
            Instant notBefore,
            Instant issuedAt,
            String jwtId,
            Map<String, JsonNode> tree,
            DeserializationContext context
    ) {
        this.issuer = issuer;
        this.subject = subject;
        this.audience = audience != null ? Collections.unmodifiableList(audience) : null;
        this.expiresAt = expiresAt;
        this.notBefore = notBefore;
        this.issuedAt = issuedAt;
        this.jwtId = jwtId;
        this.tree = tree != null ? Collections.unmodifiableMap(tree) : Collections.emptyMap();
        this.context = context;
    }

    Map<String, JsonNode> getTree() {
        return tree;
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
    public List<String> getAudience() {
        return audience;
    }

    @Override
    public Date getExpiresAt() {
        return (expiresAt != null) ? Date.from(expiresAt) : null;
    }


    @Override
    public Instant getExpiresAtAsInstant() {
        return expiresAt;
    }

    @Override
    public Date getIssuedAt() {
        return (issuedAt != null) ? Date.from(issuedAt) : null;
    }

    @Override
    public Instant getIssuedAtAsInstant() {
        return issuedAt;
    }

    @Override
    public Date getNotBefore() {
        return (notBefore != null) ? Date.from(notBefore) : null;
    }

    @Override
    public Instant getNotBeforeAsInstant() {
        return notBefore;
    }

    @Override
    public String getId() {
        return jwtId;
    }

    @Override
    public Claim getClaim(String name) {
        return extractClaim(name, tree, context);
    }

    @Override
    public Map<String, Claim> getClaims() {
        Map<String, Claim> claims = new HashMap<>(tree.size() * 2);
        for (String name : tree.keySet()) {
            claims.put(name, extractClaim(name, tree, context));
        }
        return Collections.unmodifiableMap(claims);
    }
}
