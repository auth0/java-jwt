package com.auth0.jwtdecodejava.impl;

import com.auth0.jwtdecodejava.interfaces.Claim;
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
        return data.isNull();
    }

    @Override
    public Boolean asBoolean() {
        return isNull() ? null : data.asBoolean();
    }

    @Override
    public Integer asInt() {
        return isNull() ? null : data.asInt();
    }

    @Override
    public Double asDouble() {
        return isNull() ? null : data.asDouble();
    }

    @Override
    public String asString() {
        return isNull() ? null : data.asText();
    }

    @Override
    public Date asDate() {
        if (isNull()) {
            return null;
        }
        long seconds = data.asLong();
        return new Date(seconds * 1000);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T[] asArray(Class<T> tClazz) throws Exception {
        if (data.isNull() || !data.isArray()) {
            return (T[]) Array.newInstance(tClazz, 0);
        }

        ObjectMapper mapper = new ObjectMapper();
        T[] arr = (T[]) Array.newInstance(tClazz, data.size());
        for (int i = 0; i < data.size(); i++) {
            arr[i] = mapper.treeToValue(data.get(i), tClazz);
        }
        return arr;
    }

    @Override
    public <T> List<T> asList(Class<T> tClazz) throws Exception {
        if (data.isNull() || !data.isArray()) {
            return new ArrayList<>(0);
        }

        ObjectMapper mapper = new ObjectMapper();
        List<T> list = new ArrayList<>();
        for (int i = 0; i < data.size(); i++) {
            list.add(mapper.treeToValue(data.get(i), tClazz));
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
        if (node.isObject() && node.size() == 0) {
            return new NullClaim();
        }
        return new ClaimImpl(node);
    }
}
