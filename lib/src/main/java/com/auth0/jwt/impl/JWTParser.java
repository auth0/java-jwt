package com.auth0.jwt.impl;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Header;
import com.auth0.jwt.interfaces.JWTPartsParser;
import com.auth0.jwt.interfaces.Payload;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;

public class JWTParser implements JWTPartsParser {
    private final ObjectReader payloadReader;
    private final ObjectReader headerReader;

    public JWTParser() {
        this(getDefaultObjectMapper());
    }

    JWTParser(@NotNull ObjectMapper mapper) {
        addDeserializers(mapper);
        this.payloadReader = mapper.readerFor(Payload.class);
        this.headerReader = mapper.readerFor(Header.class);
    }

    @NotNull
    @Override
    public Payload parsePayload(@NotNull String json) throws JWTDecodeException {
        if (json == null) {
            throw decodeException();
        }

        try {
            return payloadReader.readValue(json);
        } catch (IOException e) {
            throw decodeException(json);
        }
    }

    @NotNull
    @Override
    public Header parseHeader(@NotNull String json) throws JWTDecodeException {
        if (json == null) {
            throw decodeException();
        }

        try {
            return headerReader.readValue(json);
        } catch (IOException e) {
            throw decodeException(json);
        }
    }

    private void addDeserializers(ObjectMapper mapper) {
        SimpleModule module = new SimpleModule();
        ObjectReader reader = mapper.reader();
        module.addDeserializer(Payload.class, new PayloadDeserializer(reader));
        module.addDeserializer(Header.class, new HeaderDeserializer(reader));
        mapper.registerModule(module);
    }

    static ObjectMapper getDefaultObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
        mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
        return mapper;
    }

    private static JWTDecodeException decodeException() {
        return decodeException(null);
    }

    private static JWTDecodeException decodeException(String json) {
        return new JWTDecodeException(String.format("The string '%s' doesn't have a valid JSON format.", json));
    }
}
