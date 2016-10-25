package com.auth0.jwtdecodejava.impl;

import com.auth0.jwtdecodejava.exceptions.JWTException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import java.io.IOException;
import java.util.Map;

public class HeaderDeserializer extends StdDeserializer<HeaderImpl> {

    public HeaderDeserializer() {
        this(null);
    }

    protected HeaderDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public HeaderImpl deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        Map<String, JsonNode> tree = p.getCodec().readValue(p, new TypeReference<Map<String, JsonNode>>() {
        });
        if (tree == null) {
            throw new JWTException("Null map");
        }
        return new HeaderImpl(tree);
    }
}
