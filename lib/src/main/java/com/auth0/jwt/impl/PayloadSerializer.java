package com.auth0.jwt.impl;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Jackson serializer implementation for converting into JWT Payload parts.
 *
 * @see com.auth0.jwt.JWTCreator
 * <p>
 * This class is thread-safe.
 */
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
                gen.writeFieldName(e.getKey());
                handleSerialization(e.getValue(), gen);
            }
        }

        gen.writeEndObject();
    }

    /**
     * Serializes {@linkplain Instant} to epoch second values, traversing maps and lists as needed.
     * @param value the object to serialize
     * @param gen the JsonGenerator to use for JSON serialization
     * @throws IOException
     */
    private void handleSerialization(Object value, JsonGenerator gen) throws IOException {
        if (value instanceof Instant) { // EXPIRES_AT, ISSUED_AT, NOT_BEFORE, custom Instant claims
            gen.writeNumber(instantToSeconds((Instant) value));
        } else if (value instanceof Date) {
            gen.writeNumber(dateToSeconds((Date) value));
        } else if (value instanceof Map) {
            serializeMap((Map<?, ?>) value, gen);
        } else if (value instanceof List) {
            serializeList((List<?>) value, gen);
        } else {
            gen.writeObject(value);
        }
    }

    private void serializeMap(Map<?, ?> map, JsonGenerator gen) throws IOException {
        gen.writeStartObject();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            gen.writeFieldName((String) entry.getKey());
            Object value = entry.getValue();
            handleSerialization(value, gen);
        }
        gen.writeEndObject();
    }

    private void serializeList(List<?> list, JsonGenerator gen) throws IOException {
        gen.writeStartArray();
        for (Object entry : list) {
            handleSerialization(entry, gen);
        }
        gen.writeEndArray();
    }

    private long instantToSeconds(Instant instant) {
        return instant.getEpochSecond();
    }

    private long dateToSeconds(Date date) {
        return date.getTime() / 1000;
    }
}
