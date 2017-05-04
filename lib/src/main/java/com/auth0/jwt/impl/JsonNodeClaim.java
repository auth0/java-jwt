package com.auth0.jwt.impl;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * The JsonNodeClaim retrieves a claim value from a JsonNode object.
 */
class JsonNodeClaim implements Claim {

    private final JsonNode data;

    private JsonNodeClaim(JsonNode node) {
        this.data = node;
    }

    @Override
    public Boolean asBoolean() {
        return !data.isBoolean() ? null : data.asBoolean();
    }

    @Override
    public Integer asInt() {
        return !data.isNumber() ? null : data.asInt();
    }

    @Override
    public Long asLong() {
        return !data.isNumber() ? null : data.asLong();
    }

    @Override
    public Double asDouble() {
        return !data.isNumber() ? null : data.asDouble();
    }

    @Override
    public String asString() {
        return !data.isTextual() ? null : data.asText();
    }

    @Override
    public Date asDate() {
        if (!data.canConvertToLong()) {
            return null;
        }
        long seconds = data.asLong();
        return new Date(seconds * 1000);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T[] asArray(Class<T> tClazz) throws JWTDecodeException {
        if (!data.isArray()) {
            return null;
        }

        ObjectMapper mapper = new ObjectMapper();
        T[] arr = (T[]) Array.newInstance(tClazz, data.size());
        for (int i = 0; i < data.size(); i++) {
            try {
                arr[i] = mapper.treeToValue(data.get(i), tClazz);
            } catch (JsonProcessingException e) {
                throw new JWTDecodeException("Couldn't map the Claim's array contents to " + tClazz.getSimpleName(), e);
            }
        }
        return arr;
    }

    @Override
    public <T> List<T> asList(Class<T> tClazz) throws JWTDecodeException {
        if (!data.isArray()) {
            return null;
        }

        ObjectMapper mapper = new ObjectMapper();
        List<T> list = new ArrayList<>();
        for (int i = 0; i < data.size(); i++) {
            try {
                list.add(mapper.treeToValue(data.get(i), tClazz));
            } catch (JsonProcessingException e) {
                throw new JWTDecodeException("Couldn't map the Claim's array contents to " + tClazz.getSimpleName(), e);
            }
        }
        return list;
    }

    @Override
    public Map<String, Object> asMap() throws JWTDecodeException {
        if (!data.isObject()) {
            return null;
        }

        ObjectMapper mapper = new ObjectMapper();
        try {
            TypeReference<Map<String, Object>> mapType = new TypeReference<Map<String, Object>>() {
            };
            return mapper.treeAsTokens(data).readValueAs(mapType);
        } catch (IOException e) {
            throw new JWTDecodeException("Couldn't map the Claim value to Map", e);
        }
    }

    @Override
    public <T> T as(Class<T> tClazz) throws JWTDecodeException {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.treeAsTokens(data).readValueAs(tClazz);
        } catch (IOException e) {
            throw new JWTDecodeException("Couldn't map the Claim value to " + tClazz.getSimpleName(), e);
        }
    }

    @Override
    public boolean isNull() {
        return false;
    }

    /**
     * Helper method to extract a Claim from the given JsonNode tree.
     *
     * @param claimName the Claim to search for.
     * @param tree      the JsonNode tree to search the Claim in.
     * @return a valid non-null Claim.
     */
    static Claim extractClaim(String claimName, Map<String, JsonNode> tree) {
        JsonNode node = tree.get(claimName);
        return claimFromNode(node);
    }

    /**
     * Helper method to create a Claim representation from the given JsonNode.
     *
     * @param node the JsonNode to convert into a Claim.
     * @return a valid Claim instance. If the node is null or missing, a NullClaim will be returned.
     */
    static Claim claimFromNode(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return new NullClaim();
        }
        return new JsonNodeClaim(node);
    }
}
