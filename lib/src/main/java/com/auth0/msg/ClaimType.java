package com.auth0.msg;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.List;

/**
 * This enum specifies the claims and their allowed values to enable validation of messages
 */
public enum ClaimType {
//    GRANT_TYPE("grant_type", Arrays.asList("refresh_token")),
//    ERROR("error", Arrays.asList("invalid_request", "unauthorized_client")),
//    ISSUER("issuer", Arrays.asList("*")),
//    CLIENT_ID("client_id", Arrays.asList("*")),
//    KEY_JAR("key_jar", Arrays.asList("*")),
//    SHOULD_VERIFY("should_verify", Arrays.asList("*"));
//
//    private final String name;
//    private final List<String> allowedValues;
//
//    ClaimType(String name, List<String> allowedValues) {
//        this.name = name;
//        this.allowedValues = allowedValues;
//    }
    STRING("String", String.class),
    INT("Int", int.class),
    LIST("List", List.class),
    ARRAY("Array", Array.class);

    private final String type;
    private final Class classType;
    ClaimType(String type, Class classType) {
        this.type = type;
        this.classType = classType;
    }
}