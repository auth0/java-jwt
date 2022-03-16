package com.auth0.jwt.impl;

import org.hamcrest.collection.IsMapContaining;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.*;
import static org.hamcrest.MatcherAssert.assertThat;

public class PayloadClaimsHolderTest {

    @Test
    public void shouldGetClaims() {
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("iss", "auth0");
        ClaimsHolder holder = new PayloadClaimsHolder(claims);
        assertThat(holder, is(notNullValue()));
        assertThat(holder.getClaims(), is(notNullValue()));
        assertThat(holder.getClaims(), is(instanceOf(Map.class)));
        assertThat(holder.getClaims(), is(IsMapContaining.hasEntry("iss", "auth0")));
    }

    @Test
    public void shouldGetNotNullClaims() {
        ClaimsHolder holder = new PayloadClaimsHolder(null);
        assertThat(holder, is(notNullValue()));
        assertThat(holder.getClaims(), is(notNullValue()));
        assertThat(holder.getClaims(), is(instanceOf(Map.class)));
    }
}