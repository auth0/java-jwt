package com.auth0.jwtdecodejava.enums;

import org.apache.commons.codec.digest.HmacAlgorithms;

public enum HSAlgorithm implements Algorithm {
    HS256(HmacAlgorithms.HMAC_SHA_256.toString()),
    HS384(HmacAlgorithms.HMAC_SHA_384.toString()),
    HS512(HmacAlgorithms.HMAC_SHA_512.toString());

    private final String description;

    HSAlgorithm(String description) {
        this.description = description;
    }

    @Override
    public String describe() {
        return description;
    }

    public static Algorithm resolveFrom(String name) {
        try {
            return valueOf(name);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }
}
