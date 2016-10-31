package com.auth0.jwtdecodejava.impl;

import com.auth0.jwtdecodejava.exceptions.JWTDecodeException;
import com.auth0.jwtdecodejava.interfaces.Claim;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * The ClaimImpl class implements the Claim interface.
 */
class ClaimImpl extends BaseClaim {

    private final JsonNode data;

    private ClaimImpl(JsonNode node) {
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
     * @return a valid Claim instance. If the node is null or missing, a BaseClaim will be returned.
     */
    static Claim claimFromNode(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return new BaseClaim();
        }
        return new ClaimImpl(node);
    }
}
