package com.auth0.jwt.impl;

import com.auth0.jwt.HeaderParams;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Header;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import java.io.IOException;
import java.util.Map;

/**
 * Jackson deserializer implementation for converting from JWT Header parts.
 * <p>
 * This class is thread-safe.
 *
 * @see JWTParser
 */
class HeaderDeserializer extends StdDeserializer<Header> {

    HeaderDeserializer() {
        super(Header.class);
    }

    @Override
    public Header deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        Map<String, JsonNode> tree = p.getCodec().readValue(p, new TypeReference<Map<String, JsonNode>>() {
        });
        if (tree == null) {
            throw new JWTDecodeException("Parsing the Header's JSON resulted on a Null map");
        }

        String algorithm = getString(tree, HeaderParams.ALGORITHM.getValue());
        String type = getString(tree, HeaderParams.TYPE.getValue());
        String contentType = getString(tree, HeaderParams.CONTENT_TYPE.getValue());
        String keyId = getString(tree, HeaderParams.KEY_ID.getValue());
        return new BasicHeader(algorithm, type, contentType, keyId, tree, p.getCodec());
    }

    String getString(Map<String, JsonNode> tree, String claimName) {
        JsonNode node = tree.get(claimName);
        if (node == null || node.isNull()) {
            return null;
        }
        return node.asText(null);
    }
}
