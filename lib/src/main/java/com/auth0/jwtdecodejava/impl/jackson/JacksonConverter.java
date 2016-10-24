package com.auth0.jwtdecodejava.impl.jackson;

import com.auth0.jwtdecodejava.interfaces.Header;
import com.auth0.jwtdecodejava.interfaces.Payload;
import com.auth0.jwtdecodejava.interfaces.JsonConverter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

import java.io.IOException;

public class JacksonConverter implements JsonConverter {
    private ObjectMapper mapper;

    public JacksonConverter(ObjectMapper mapper) {
        configureMapper(mapper);
        this.mapper = mapper;
    }

    @Override
    public <T> String toJson(T object, Class<T> tClazz) throws IOException {
        return mapper.writeValueAsString(object);
    }

    @Override
    public <T> T fromJson(String json, Class<T> tClazz) throws IOException {
        return mapper.readValue(json, tClazz);
    }

    public Payload parsePayload(String json) throws IOException {
        return mapper.readValue(json, Payload.class);
    }

    public Header parseHeader(String json) throws IOException {
        return null;//mapper.readValue(json, HeaderImpl.class);
    }

    private void configureMapper(ObjectMapper mapper) {
        mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);

        SimpleModule module = new SimpleModule();
        module.addDeserializer(Payload.class, new PayloadDeserializer());
        mapper.registerModule(module);
    }
}
