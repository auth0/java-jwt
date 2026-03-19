package com.auth0.jwt.impl;

import com.auth0.jwt.HeaderParams;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Header;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.deser.std.StdDeserializer;

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
    public Header deserialize(JsonParser p, DeserializationContext ctxt) throws JacksonException {
        Map<String, JsonNode> tree = ctxt.readValue(p, new TypeReference<>() {
        });
        if (tree == null) {
            throw new JWTDecodeException("Parsing the Header's JSON resulted on a Null map");
        }

        String algorithm = getString(tree, HeaderParams.ALGORITHM);
        String type = getString(tree, HeaderParams.TYPE);
        String contentType = getString(tree, HeaderParams.CONTENT_TYPE);
        String keyId = getString(tree, HeaderParams.KEY_ID);
        return new BasicHeader(algorithm, type, contentType, keyId, tree, ctxt);
    }

    String getString(Map<String, JsonNode> tree, String claimName) {
        JsonNode node = tree.get(claimName);
        if (node == null || node.isNull()) {
            return null;
        }
        return node.asString(null);
    }
}
