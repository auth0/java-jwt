package com.auth0.jwt.impl;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import java.io.IOException;
import java.util.Map;

class HeaderDeserializer extends StdDeserializer<HeaderImpl> {

    HeaderDeserializer() {
        this(null);
    }

    private HeaderDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public HeaderImpl deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        Map<String, JsonNode> tree = p.getCodec().readValue(p, new TypeReference<Map<String, JsonNode>>() {
        });
        if (tree == null) {
            throw new JWTDecodeException("Parsing the Header's JSON resulted on a Null map");
        }
        return new HeaderImpl(tree);
    }
}
