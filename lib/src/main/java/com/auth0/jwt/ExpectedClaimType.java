package com.auth0.jwt;

import com.auth0.jwt.interfaces.Clock;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Map;

public interface ExpectedClaimType {
    void assertExpectedClaimType(DecodedJWT jwt, Map.Entry<String, Object> entry, Clock clock);
}
