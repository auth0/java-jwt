package com.auth0.jwt.impl;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.lang.reflect.Array;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static com.auth0.jwt.impl.JWTParser.getDefaultObjectMapper;

/**
 * The JsonNodeClaim retrieves a claim value from a JsonNode object.
 */
class JsonNodeClaim implements Claim {

    private final DeserializationContext context;
    private final JsonNode data;
    private final ObjectMapper mapper = getDefaultObjectMapper();

    private JsonNodeClaim(JsonNode node, DeserializationContext context) {
        this.data = node;
        this.context = context;
    }

    @Override
    public Boolean asBoolean() {
        return isMissing() || isNull() || !data.isBoolean() ? null : data.asBoolean();
    }

    @Override
    public Integer asInt() {
        return isMissing() || isNull() || !data.isNumber() ? null : data.asInt();
    }

    @Override
    public Long asLong() {
        return isMissing() || isNull() || !data.isNumber() ? null : data.asLong();
    }

    @Override
    public Double asDouble() {
        return isMissing() || isNull() || !data.isNumber() ? null : data.asDouble();
    }

    @Override
    public String asString() {
        return isMissing() || isNull() || !data.isString() ? null : data.asString();
    }

    @Override
    public Date asDate() {
        if (isMissing() || isNull() || !data.canConvertToLong()) {
            return null;
        }
        long seconds = data.asLong();
        return new Date(seconds * 1000);
    }

    @Override
    public Instant asInstant() {
        if (isMissing() || isNull() || !data.canConvertToLong()) {
            return null;
        }
        long seconds = data.asLong();
        return Instant.ofEpochSecond(seconds);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T[] asArray(Class<T> clazz) throws JWTDecodeException {
        if (isMissing() || isNull() || !data.isArray()) {
            return null;
        }

        T[] arr = (T[]) Array.newInstance(clazz, data.size());
        for (int i = 0; i < data.size(); i++) {
            try {
                arr[i] = context.readTreeAsValue(data.get(i), clazz);
            } catch (JacksonException e) {
                throw new JWTDecodeException("Couldn't map the Claim's array contents to " + clazz.getSimpleName(), e);
            }
        }
        return arr;
    }

    @Override
    public <T> List<T> asList(Class<T> clazz) throws JWTDecodeException {
        if (isMissing() || isNull() || !data.isArray()) {
            return null;
        }

        List<T> list = new ArrayList<>();
        for (int i = 0; i < data.size(); i++) {
            try {
                list.add(context.readTreeAsValue(data.get(i), clazz));
            } catch (JacksonException e) {
                throw new JWTDecodeException("Couldn't map the Claim's array contents to " + clazz.getSimpleName(), e);
            }
        }
        return list;
    }

    @Override
    public Map<String, Object> asMap() throws JWTDecodeException {
        if (isMissing() || isNull() || !data.isObject()) {
            return null;
        }

        try {
            return mapper.convertValue(data, new TypeReference<>() {});
        } catch (Exception e) {
            throw new JWTDecodeException("Couldn't map the Claim value to Map", e);
        }
    }

    @Override
    public <T> T as(Class<T> clazz) throws JWTDecodeException {
        try {
            if (isMissing() || isNull()) {
                return null;
            }

            return mapper.convertValue(data, clazz);
        } catch (JacksonException e) {
            throw new JWTDecodeException("Couldn't map the Claim value to " + clazz.getSimpleName(), e);
        }
    }

    @Override
    public boolean isNull() {
        return !isMissing() && data.isNull();
    }

    @Override
    public boolean isMissing() {
        return data == null || data.isMissingNode();
    }

    @Override
    public String toString() {
        if (isMissing()) {
            return "Missing claim";
        } else if (isNull()) {
            return "Null claim";
        }
        return data.toString();
    }

    /**
     * Helper method to extract a Claim from the given JsonNode tree.
     *
     * @param claimName the Claim to search for.
     * @param tree      the JsonNode tree to search the Claim in.
     * @param context the context in use for deserialization
     * @return a valid non-null Claim.
     */
    static Claim extractClaim(String claimName, Map<String, JsonNode> tree, DeserializationContext context) {
        JsonNode node = tree.get(claimName);
        return claimFromNode(node, context);
    }

    /**
     * Helper method to create a Claim representation from the given JsonNode.
     *
     * @param node the JsonNode to convert into a Claim.
     * @param context the context in use for deserialization
     * @return a valid Claim instance. If the node is null or missing, a NullClaim will be returned.
     */
    static Claim claimFromNode(JsonNode node, DeserializationContext context) {
        return new JsonNodeClaim(node, context);
    }

}