package com.auth0.jwtdecodejava.algorithms;

public enum NoneAlgorithm implements Algorithm {
    none("none");

    private final String description;

    NoneAlgorithm(String description) {
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
