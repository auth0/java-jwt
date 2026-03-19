package com.auth0.jwt.impl;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Header;
import com.auth0.jwt.interfaces.JWTPartsParser;
import com.auth0.jwt.interfaces.Payload;
import com.fasterxml.jackson.annotation.JsonInclude;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.ObjectReader;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.module.SimpleModule;

/**
 * This class helps in decoding the Header and Payload of the JWT using
 * {@link HeaderSerializer} and {@link PayloadSerializer}.
 */
public class JWTParser implements JWTPartsParser {
    private static final ObjectMapper DEFAULT_OBJECT_MAPPER = createDefaultObjectMapper();
    private static final ObjectReader DEFAULT_PAYLOAD_READER = DEFAULT_OBJECT_MAPPER.readerFor(Payload.class);
    private static final ObjectReader DEFAULT_HEADER_READER = DEFAULT_OBJECT_MAPPER.readerFor(Header.class);

    private final ObjectReader payloadReader;
    private final ObjectReader headerReader;

    public JWTParser() {
        this.payloadReader = DEFAULT_PAYLOAD_READER;
        this.headerReader = DEFAULT_HEADER_READER;
    }

    JWTParser(ObjectMapper mapper) {
        this.payloadReader = mapper.readerFor(Payload.class);
        this.headerReader = mapper.readerFor(Header.class);
    }

    @Override
    public Payload parsePayload(String json) throws JWTDecodeException {
        if (json == null) {
            throw decodeException();
        }

        try {
            return payloadReader.readValue(json);
        } catch (JacksonException e) {
            throw decodeException(json);
        }
    }

    @Override
    public Header parseHeader(String json) throws JWTDecodeException {
        if (json == null) {
            throw decodeException();
        }

        try {
            return headerReader.readValue(json);
        } catch (JacksonException e) {
            throw decodeException(json);
        }
    }

    static void addDeserializers(JsonMapper.Builder builder) {
        SimpleModule module = new SimpleModule();
        module.addDeserializer(Payload.class, new PayloadDeserializer());
        module.addDeserializer(Header.class, new HeaderDeserializer());
        builder.addModule(module);
    }

    static ObjectMapper getDefaultObjectMapper() {
        return DEFAULT_OBJECT_MAPPER;
    }

    private static ObjectMapper createDefaultObjectMapper() {
        JsonMapper.Builder builder = JsonMapper.builder()
                .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
                .changeDefaultPropertyInclusion(incl -> incl.withValueInclusion(JsonInclude.Include.NON_EMPTY));

        addDeserializers(builder);

        return builder.build();
    }

    private static JWTDecodeException decodeException() {
        return decodeException(null);
    }

    private static JWTDecodeException decodeException(String json) {
        return new JWTDecodeException(String.format("The string '%s' doesn't have a valid JSON format.", json));
    }
}