package com.auth0.jwt.impl;

import java.util.HashMap;
import java.util.Map;

/**
 * The ClaimsHolder class is just a wrapper for the Map of Claims.
 */
public final class ClaimsHolder {
    private Map<String, Object> claims;

    public ClaimsHolder(Map<String, Object> claims) {
        this.claims = claims == null ? new HashMap<String, Object>() : claims;
    }

    Map<String, Object> getClaims() {
        return claims;
    }
}
