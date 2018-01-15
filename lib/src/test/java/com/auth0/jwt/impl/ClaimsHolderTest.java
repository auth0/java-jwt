package com.auth0.jwt.impl;

import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;

import java.util.HashMap;
import java.util.Map;

import org.hamcrest.collection.IsMapContaining;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

public class ClaimsHolderTest {

	@SuppressWarnings("RedundantCast")
	@Test
	public void shouldGetClaims() throws Exception {
		HashMap<String, Object> claims = new HashMap<String, Object>();
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