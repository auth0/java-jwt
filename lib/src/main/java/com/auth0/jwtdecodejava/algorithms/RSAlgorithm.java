package com.auth0.jwtdecodejava.algorithms;

public enum RSAlgorithm implements Algorithm {
    RS256("SHA256withRSA"),
    RS384("SHA384withRSA"),
    RS512("SHA512withRSA");

    private final String description;

    RSAlgorithm(String description) {
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
