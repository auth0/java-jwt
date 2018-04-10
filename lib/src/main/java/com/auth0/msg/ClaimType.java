package com.auth0.msg;

import java.util.Arrays;
import java.util.List;

public enum ClaimType {

    GRANT_TYPE("grant_type", Arrays.asList("refresh_token")),
    ERROR("error", Arrays.asList("invalid_request", "unauthorized_client"));

    private final String name;
    private final List<String> allowedValues;

    ClaimType(String name, List<String> allowedValues) {
        this.name = name;
        this.allowedValues = allowedValues;
    }
}