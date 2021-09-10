package com.auth0.jwt.impl;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;
import java.util.*;

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
                writeAudience(gen, e);
            } else {
                gen.writeFieldName(e.getKey());
                if (e.getValue() instanceof Date) { // true for EXPIRES_AT, ISSUED_AT, NOT_BEFORE
                    gen.writeNumber(dateToSeconds((Date) e.getValue()));
                } else {
                    gen.writeObject(e.getValue());
                }
            }
        }

        gen.writeEndObject();
    }

    private void writeAudience(JsonGenerator gen, Map.Entry<String, Object> e) throws IOException {
        if (e.getValue() instanceof String) {
            gen.writeFieldName(e.getKey());
            gen.writeString((String) e.getValue());
        } else {
            List<String> audArray = new ArrayList<>();
            if (e.getValue() instanceof String[]) {
                audArray = Arrays.asList((String[]) e.getValue());
            } else if (e.getValue() instanceof List) {
                List<?> audList = (List<?>) e.getValue();
                for (Object aud : audList) {
                    if (aud instanceof String) {
                        audArray.add((String)aud);
                    }
                }
            }
            if (audArray.size() == 1) {
                gen.writeFieldName(e.getKey());
                gen.writeString(audArray.get(0));
            } else if (audArray.size() > 1) {
                gen.writeFieldName(e.getKey());
                gen.writeStartArray();
                for (String aud : audArray) {
                    gen.writeString(aud);
                }
                gen.writeEndArray();
            }
        }
    }

    private long dateToSeconds(Date date) {
        return date.getTime() / 1000;
    }
}
