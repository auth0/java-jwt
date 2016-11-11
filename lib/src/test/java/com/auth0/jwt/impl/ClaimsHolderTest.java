package com.auth0.jwt.impl;

import org.hamcrest.collection.IsMapContaining;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

public class ClaimsHolderTest {

    @SuppressWarnings("RedundantCast")
    @Test
    public void shouldGetClaims() throws Exception {
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("iss", "auth0");
        ClaimsHolder holder = new ClaimsHolder(claims);
        assertThat(holder, is(notNullValue()));
        assertThat(holder.getClaims(), is(notNullValue()));
        assertThat(holder.getClaims(), is(instanceOf(Map.class)));
        assertThat(holder.getClaims(), is(IsMapContaining.hasEntry("iss", (Object) "auth0")));
    }

    @Test
    public void shouldGetNotNullClaims() throws Exception {
        ClaimsHolder holder = new ClaimsHolder(null);
        assertThat(holder, is(notNullValue()));
        assertThat(holder.getClaims(), is(notNullValue()));
        assertThat(holder.getClaims(), is(instanceOf(Map.class)));
    }
}