package com.auth0.jwtdecodejava.impl.jackson;

import com.auth0.jwtdecodejava.impl.BaseClaim;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.istack.internal.NotNull;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class ClaimImpl extends BaseClaim {

    private final JsonNode data;

    public ClaimImpl(@NotNull String name, @NotNull JsonNode node) {
        super(name);
        this.data = node;
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
        return data.asBoolean();
    }

    @Override
    public Integer asInt() {
        return data.asInt();
    }

    @Override
    public Double asDouble() {
        return data.asDouble();
    }

    @Override
    public String asString() {
        return data.asText();
    }

    @Override
    public Date asDate() {
        long seconds = data.asLong();
        return new Date(seconds * 1000);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T[] asArray(Class<T> tClazz) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        if (!data.isArray()) {
            return (T[]) Array.newInstance(tClazz, 0);
        }

        T[] arr = (T[]) Array.newInstance(tClazz, data.size());
        for (int i = 0; i < data.size(); i++) {
            arr[i] = mapper.treeToValue(data.get(i), tClazz);
        }
        return arr;
    }

    @Override
    public <T> List<T> asList(Class<T> tClazz) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        if (!data.isArray()) {
            return new ArrayList<>(0);
        }

        List<T> list = new ArrayList<>();
        for (int i = 0; i < data.size(); i++) {
            list.add(mapper.treeToValue(data.get(i), tClazz));
        }
        return list;
    }
}
