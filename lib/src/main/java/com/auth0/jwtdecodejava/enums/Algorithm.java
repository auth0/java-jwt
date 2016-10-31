package com.auth0.jwtdecodejava.enums;

import org.apache.commons.codec.digest.HmacAlgorithms;

public enum Algorithm {
    none(null),
    HS256(HmacAlgorithms.HMAC_SHA_256.toString()),
    HS384(HmacAlgorithms.HMAC_SHA_384.toString()),
    HS512(HmacAlgorithms.HMAC_SHA_512.toString()),
    RS256("SHA256withRSA"),
    RS384("SHA384withRSA"),
    RS512("SHA512withRSA");

    private final String description;

    Algorithm(String description) {
        this.description = description;
    }

    @Override
    public String toString() {
        return description;
    }

    public static Algorithm parseFrom(String algorithmName) {
        try {
            return Algorithm.valueOf(algorithmName);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }
}
