package com.auth0.jwt.impl;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
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
        HashMap<Object, Object> safePayload = new HashMap<Object, Object>();
        for (Map.Entry<String, Object> e : holder.getClaims().entrySet()) {
            if (PublicClaims.AUDIENCE.equals(e.getKey())) {
                if (e.getValue() instanceof String) {
                    safePayload.put(e.getKey(), e.getValue());
                }
                if (e.getValue() instanceof String[]) {
                    String[] audArray = (String[]) e.getValue();
                    if (audArray.length == 1) {
                        safePayload.put(e.getKey(), audArray[0]);
                    } else if (audArray.length > 1) {
                        safePayload.put(e.getKey(), audArray);
                    }
                }
            } else if (PublicClaims.EXPIRES_AT.equals(e.getKey()) || PublicClaims.ISSUED_AT.equals(e.getKey()) || PublicClaims.NOT_BEFORE.equals(e.getKey())) {
                safePayload.put(e.getKey(), dateToSeconds((Date) e.getValue()));
            } else {
                if (e.getValue() instanceof Date) {
                    safePayload.put(e.getKey(), dateToSeconds((Date) e.getValue()));
                } else {
                    safePayload.put(e.getKey(), e.getValue());
                }
            }
        }

        gen.writeObject(safePayload);
    }

    private long dateToSeconds(Date date) {
        return date.getTime() / 1000;
    }
}
