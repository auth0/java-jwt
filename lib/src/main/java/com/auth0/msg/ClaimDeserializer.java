package com.auth0.msg;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.KeyDeserializer;

import java.io.IOException;

public class ClaimDeserializer extends KeyDeserializer {

    @Override
    public Claim deserializeKey (String key, DeserializationContext ctxt) throws IOException, JsonProcessingException {
        return new Claim(key);
    }
}
