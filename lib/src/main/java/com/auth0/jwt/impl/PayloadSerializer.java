package com.auth0.jwt.impl;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

public class PayloadSerializer extends StdSerializer<ClaimsHolder> {

    public PayloadSerializer() {
        this(null);
    }

    private PayloadSerializer(Class<ClaimsHolder> t) {
        super(t);
    }

    @Override
    public void serialize(ClaimsHolder holder, JsonGenerator gen, SerializerProvider provider) throws IOException {
        gen.writeStartObject();
        for (Map.Entry<String, Object> e : holder.getClaims().entrySet()) {
            if (PublicClaims.AUDIENCE.equals(e.getKey())) {
                if (e.getValue() instanceof String) {
                    gen.writeFieldName(e.getKey());
                    gen.writeString((String) e.getValue());
                    continue;
                }
                String[] audArray = (String[]) e.getValue();
                if (audArray.length == 1) {
                    gen.writeFieldName(e.getKey());
                    gen.writeString(audArray[0]);
                } else if (audArray.length > 1) {
                    gen.writeFieldName(e.getKey());
                    gen.writeStartArray();
                    for (String aud : audArray) {
                        gen.writeString(aud);
                    }
                    gen.writeEndArray();
                }
            } else {
                handleSerialization(e, gen);
            }
        }

        gen.writeEndObject();
    }

    /**
     * Serializes {@linkplain Instant} to epoch second values, traversing maps and lists as needed.
     * @param entry the entry to serialize
     * @param gen the JsonGenerator to use for JSON serialization
     * @throws IOException
     */
    private void handleSerialization(Map.Entry<String, Object> entry, JsonGenerator gen) throws IOException {
        gen.writeFieldName(entry.getKey());
        if (entry.getValue() instanceof Instant) { // EXPIRES_AT, ISSUED_AT, NOT_BEFORE, custom Instant claims
            gen.writeNumber(instantToSeconds((Instant) entry.getValue()));
        } else if (entry.getValue() instanceof List) {
            // traverse lists and handle custom Instant serialization
            serializeList((List<?>) entry.getValue(), gen);
        } else if (entry.getValue() instanceof Map) {
            // traverse maps and handle custom Instant serialization
            serializeMap((Map<?,?>) entry.getValue(), gen);
        } else {
            gen.writeObject(entry.getValue());
        }
    }

    private void serializeMap(Map<?, ?> map, JsonGenerator gen) throws IOException {
        gen.writeStartObject();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            gen.writeFieldName((String) entry.getKey());
            Object value = entry.getValue();
            serialize(value, gen);
        }
        gen.writeEndObject();
    }

    private void serializeList(List<?> list, JsonGenerator gen) throws IOException {
        gen.writeStartArray();
        for (Object entry : list) {
            serialize(entry, gen);
        }
        gen.writeEndArray();
    }

    private void serialize(Object value, JsonGenerator gen) throws IOException {
        if (value instanceof Instant) {
            gen.writeNumber(instantToSeconds((Instant) value));
        } else if (value instanceof Map) {
            serializeMap((Map<?, ?>) value, gen);
        } else if (value instanceof List) {
            serializeList((List<?>) value, gen);
        } else {
            gen.writeObject(value);
        }
    }

    private long instantToSeconds(Instant instant) {
        return instant.getEpochSecond();
    }
}
