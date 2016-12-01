package com.auth0.jwt.impl;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Payload;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import java.io.IOException;
import java.util.*;

class PayloadDeserializer extends StdDeserializer<Payload> {

    PayloadDeserializer() {
        this(null);
    }

    private PayloadDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public Payload deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        Map<String, JsonNode> tree = p.getCodec().readValue(p, new TypeReference<Map<String, JsonNode>>() {
        });
        if (tree == null) {
            throw new JWTDecodeException("Parsing the Payload's JSON resulted on a Null map");
        }

        String issuer = getString(tree, PublicClaims.ISSUER);
        String subject = getString(tree, PublicClaims.SUBJECT);
        List<String> audience = getStringOrArray(tree, PublicClaims.AUDIENCE);
        Date expiresAt = getDateFromSeconds(tree, PublicClaims.EXPIRES_AT);
        Date notBefore = getDateFromSeconds(tree, PublicClaims.NOT_BEFORE);
        Date issuedAt = getDateFromSeconds(tree, PublicClaims.ISSUED_AT);
        String jwtId = getString(tree, PublicClaims.JWT_ID);

        return new PayloadImpl(issuer, subject, audience, expiresAt, notBefore, issuedAt, jwtId, tree);
    }

    List<String> getStringOrArray(Map<String, JsonNode> tree, String claimName) throws JWTDecodeException {
        JsonNode node = tree.get(claimName);
        if (node == null || node.isNull() || !(node.isArray() || node.isTextual())) {
            return null;
        }
        if (node.isTextual() && !node.asText().isEmpty()) {
            return Collections.singletonList(node.asText());
        }

        ObjectMapper mapper = new ObjectMapper();
        List<String> list = new ArrayList<>(node.size());
        for (int i = 0; i < node.size(); i++) {
            try {
                list.add(mapper.treeToValue(node.get(i), String.class));
            } catch (JsonProcessingException e) {
                throw new JWTDecodeException("Couldn't map the Claim's array contents to String", e);
            }
        }
        return list;
    }

    Date getDateFromSeconds(Map<String, JsonNode> tree, String claimName) {
        JsonNode node = tree.get(claimName);
        if (node == null || node.isNull() || !node.canConvertToLong()) {
            return null;
        }
        final long ms = node.asLong() * 1000;
        return new Date(ms);
    }

    String getString(Map<String, JsonNode> tree, String claimName) {
        JsonNode node = tree.get(claimName);
        if (node == null || node.isNull()) {
            return null;
        }
        return node.asText(null);
    }
}
