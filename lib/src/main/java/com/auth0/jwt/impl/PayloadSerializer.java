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
        HashMap<Object, Object> safePayload = new HashMap<>();
        for (Map.Entry<String, Object> e : holder.getClaims().entrySet()) {
            switch (e.getKey()) {
                case PublicClaims.AUDIENCE:
                    if (e.getValue() instanceof String) {
                        safePayload.put(e.getKey(), e.getValue());
                        break;
                    }
                    String[] audArray = (String[]) e.getValue();
                    if (audArray.length == 1) {
                        safePayload.put(e.getKey(), audArray[0]);
                    } else if (audArray.length > 1) {
                        safePayload.put(e.getKey(), audArray);
                    }
                    break;
                case PublicClaims.EXPIRES_AT:
                case PublicClaims.ISSUED_AT:
                case PublicClaims.NOT_BEFORE:
                    safePayload.put(e.getKey(), dateToSeconds((Date) e.getValue()));
                    break;
                default:
                    if (e.getValue() instanceof Date) {
                        safePayload.put(e.getKey(), dateToSeconds((Date) e.getValue()));
                    } else {
                        safePayload.put(e.getKey(), e.getValue());
                    }
                    break;
            }
        }

        gen.writeObject(safePayload);
    }

    private int dateToSeconds(Date date) {
        return (int) (date.getTime() / 1000);
    }
}
