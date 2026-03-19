package com.auth0.jwt.impl;

import com.auth0.jwt.RegisteredClaims;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Payload;
import tools.jackson.core.JsonParser;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.core.JacksonException;

import java.time.Instant;
import java.util.*;

/**
 * Jackson deserializer implementation for converting from JWT Payload parts.
 * <p>
 * This class is thread-safe.
 *
 * @see JWTParser
 */
class PayloadDeserializer extends StdDeserializer<Payload> {

    PayloadDeserializer() {
        super(Payload.class);
    }

    @Override
    public Payload deserialize(JsonParser p, DeserializationContext ctxt) {
        Map<String, JsonNode> tree = ctxt.readValue(p, new TypeReference<Map<String, JsonNode>>() {
        });
        if (tree == null) {
            throw new JWTDecodeException("Parsing the Payload's JSON resulted on a Null map");
        }

        String issuer = getString(tree, RegisteredClaims.ISSUER);
        String subject = getString(tree, RegisteredClaims.SUBJECT);
        List<String> audience = getStringOrArray(ctxt, tree, RegisteredClaims.AUDIENCE);
        Instant expiresAt = getInstantFromSeconds(tree, RegisteredClaims.EXPIRES_AT);
        Instant notBefore = getInstantFromSeconds(tree, RegisteredClaims.NOT_BEFORE);
        Instant issuedAt = getInstantFromSeconds(tree, RegisteredClaims.ISSUED_AT);
        String jwtId = getString(tree, RegisteredClaims.JWT_ID);

        return new PayloadImpl(issuer, subject, audience, expiresAt, notBefore, issuedAt, jwtId, tree, ctxt);
    }

    List<String> getStringOrArray(DeserializationContext context, Map<String, JsonNode> tree, String claimName)
            throws JWTDecodeException {
        JsonNode node = tree.get(claimName);
        if (node == null || node.isNull() || !(node.isArray() || node.isString())) {
            return null;
        }
        if (node.isString()) {
            return Collections.singletonList(node.asString());
        }

        List<String> list = new ArrayList<>(node.size());
        for (int i = 0; i < node.size(); i++) {
            try {
                list.add(context.readTreeAsValue(node.get(i), String.class));
            } catch (JacksonException e) {
                throw new JWTDecodeException("Couldn't map the Claim's array contents to String", e);
            }
        }
        return list;
    }

    Instant getInstantFromSeconds(Map<String, JsonNode> tree, String claimName) {
        JsonNode node = tree.get(claimName);
        if (node == null || node.isNull()) {
            return null;
        }
        if (!node.canConvertToLong()) {
            throw new JWTDecodeException(
                    String.format("The claim '%s' contained a non-numeric date value.", claimName));
        }
        return Instant.ofEpochSecond(node.asLong());
    }

    String getString(Map<String, JsonNode> tree, String claimName) {
        JsonNode node = tree.get(claimName);
        if (node == null || node.isNull()) {
            return null;
        }
        return node.asString(null);
    }
}
