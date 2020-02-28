package com.auth0.jwt.impl;

import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

public class NullClaimTest {
    private NullClaim claim;

    @Before
    public void setUp() {
        claim = new NullClaim();
    }

    @Test
    public void shouldBeNull() {
        assertThat(claim.isNull(), is(true));
    }

    @Test
    public void shouldGetAsBoolean() {
        assertThat(claim.asBoolean(), is(nullValue()));
    }

    @Test
    public void shouldGetAsInt() {
        assertThat(claim.asInt(), is(nullValue()));
    }

    @Test
    public void shouldGetAsLong() {
        assertThat(claim.asLong(), is(nullValue()));
    }

    @Test
    public void shouldGetAsDouble() {
        assertThat(claim.asDouble(), is(nullValue()));
    }

    @Test
    public void shouldGetAsString() {
        assertThat(claim.asString(), is(nullValue()));
    }

    @Test
    public void shouldGetAsDate() {
        assertThat(claim.asDate(), is(nullValue()));
    }

    @Test
    public void shouldGetAsArray() {
        assertThat(claim.asArray(Object.class), is(nullValue()));
    }

    @Test
    public void shouldGetAsList() {
        assertThat(claim.asList(Object.class), is(nullValue()));
    }

    @Test
    public void shouldGetAsMap() {
        assertThat(claim.asMap(), is(nullValue()));
    }

    @Test
    public void shouldGetAsCustomClass() {
        assertThat(claim.as(Object.class), is(nullValue()));
    }
}
