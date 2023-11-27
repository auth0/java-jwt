package com.auth0.jwt;

/**
 * Contains constants representing the JWT header parameter names.
 */

public enum HeaderParams {

    ALGORITHM("alg"),
    CONTENT_TYPE("cty"),
    TYPE("typ"),
    KEY_ID("kid");

    private final String value;

    HeaderParams(String value) {
        this.value = value;
    }

    /**
     * Gets the value of enum.
     *
     * @return string value of HeaderParams.
     */
    public String getValue() {
        return value;
    }
}
