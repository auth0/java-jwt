package com.auth0.jwt;

public enum Claim {
    NOTBEFORE("nbf");

    private Claim(String value) {
        this.value = value;
    }

    private String value;

    public String getValue() {
        return value;
    }
}
