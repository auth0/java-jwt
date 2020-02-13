package com.auth0.jwt.impl;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;
import java.time.Instant;
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

    private long instantToSeconds(Instant instant) {
        return instant.getEpochSecond();
    }
}
