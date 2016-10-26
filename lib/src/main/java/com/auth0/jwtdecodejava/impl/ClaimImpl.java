package com.auth0.jwtdecodejava.impl;

import com.auth0.jwtdecodejava.exceptions.JWTException;
import com.auth0.jwtdecodejava.interfaces.Claim;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.NullNode;
import com.sun.istack.internal.NotNull;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class ClaimImpl implements Claim {

    private final JsonNode data;

    public ClaimImpl(@NotNull JsonNode node) {
        this.data = node == null ? NullNode.getInstance() : node;
    }

    @Override
    public boolean isMissing() {
        return data.isMissingNode();
    }

    @Override
    public boolean isNull() {
        return data.isNull() || data.isObject() && data.size() == 0;
    }

    @Override
    public Boolean asBoolean() {
        return isNull() || !data.isBoolean() ? null : data.asBoolean();
    }

    @Override
    public Integer asInt() {
        return isNull() || !data.isNumber() ? null : data.asInt();
    }

    @Override
    public Double asDouble() {
        return isNull() || !data.isNumber() ? null : data.asDouble();
    }

    @Override
    public String asString() {
        return isNull() || !data.isTextual() ? null : data.asText();
    }

    @Override
    public Date asDate() {
        if (isNull() || !data.canConvertToLong()) {
            return null;
        }
        long seconds = data.asLong();
        return new Date(seconds * 1000);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T[] asArray(Class<T> tClazz) throws JWTException {
        if (data.isNull() || !data.isArray()) {
            return (T[]) Array.newInstance(tClazz, 0);
        }

        ObjectMapper mapper = new ObjectMapper();
        T[] arr = (T[]) Array.newInstance(tClazz, data.size());
        for (int i = 0; i < data.size(); i++) {
            try {
                arr[i] = mapper.treeToValue(data.get(i), tClazz);
            } catch (JsonProcessingException e) {
                throw new JWTException("Couldn't map the Claim's array contents to " + tClazz.getSimpleName(), e);
            }
        }
        return arr;
    }

    @Override
    public <T> List<T> asList(Class<T> tClazz) throws JWTException {
        if (data.isNull() || !data.isArray()) {
            return new ArrayList<>(0);
        }

        ObjectMapper mapper = new ObjectMapper();
        List<T> list = new ArrayList<>();
        for (int i = 0; i < data.size(); i++) {
            try {
                list.add(mapper.treeToValue(data.get(i), tClazz));
            } catch (JsonProcessingException e) {
                throw new JWTException("Couldn't map the Claim's array contents to " + tClazz.getSimpleName(), e);
            }
        }
        return list;
    }

    public static Claim extractClaim(@NotNull String claimName, @NotNull Map<String, JsonNode> tree) {
        JsonNode node = tree.get(claimName);
        return claimFromNode(node);
    }

    @NotNull
    public static Claim claimFromNode(JsonNode node) {
        if (node == null || node.isMissingNode()) {
            return new MissingClaim();
        }
        return new ClaimImpl(node);
    }
}
