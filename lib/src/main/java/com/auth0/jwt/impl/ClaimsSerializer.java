package com.auth0.jwt.impl;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.ser.std.StdSerializer;
import tools.jackson.databind.SerializationContext;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Custom serializer used to write the resulting JWT.
 *
 * @param <T> the type this serializer operates on.
 */
public class ClaimsSerializer<T extends ClaimsHolder> extends StdSerializer<T> {

    public ClaimsSerializer(Class<T> t) {
        super(t);
    }

    @Override
    public void serialize(T holder, JsonGenerator gen, SerializationContext provider) throws JacksonException {
        gen.writeStartObject();
        for (Map.Entry<String, Object> entry : holder.getClaims().entrySet()) {
            writeClaim(entry, gen);
        }
        gen.writeEndObject();
    }

    /**
     * Writes the given entry to the JSON representation. Custom claim serialization handling can override this method
     * to provide use-case specific serialization. Implementors who override this method must write
     * the field name and the field value.
     *
     * @param entry The entry that corresponds to the JSON field to write
     * @param gen The {@code JsonGenerator} to use
     * @throws JacksonException if there is either an underlying I/O problem or encoding issue at format layer
     */
    protected void writeClaim(Map.Entry<String, Object> entry, JsonGenerator gen) throws JacksonException {
        gen.writeName(entry.getKey());
        handleSerialization(entry.getValue(), gen);
    }

    private static void handleSerialization(Object value, JsonGenerator gen) throws JacksonException {
        if (value instanceof Date) {
            gen.writeNumber(dateToSeconds((Date) value));
        } else if (value instanceof Instant) { // EXPIRES_AT, ISSUED_AT, NOT_BEFORE, custom Instant claims
            gen.writeNumber(instantToSeconds((Instant) value));
        } else if (value instanceof Map) {
            serializeMap((Map<?, ?>) value, gen);
        } else if (value instanceof List) {
            serializeList((List<?>) value, gen);
        } else {
            gen.writePOJO(value);
        }
    }

    private static void serializeMap(Map<?, ?> map, JsonGenerator gen) throws JacksonException {
        gen.writeStartObject();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            gen.writeName((String) entry.getKey());
            Object value = entry.getValue();
            handleSerialization(value, gen);
        }
        gen.writeEndObject();
    }

    private static void serializeList(List<?> list, JsonGenerator gen) throws JacksonException {
        gen.writeStartArray();
        for (Object entry : list) {
            handleSerialization(entry, gen);
        }
        gen.writeEndArray();
    }

    private static long instantToSeconds(Instant instant) {
        return instant.getEpochSecond();
    }

    private static long dateToSeconds(Date date) {
        return date.getTime() / 1000;
    }
}
