package com.auth0.jwt.impl;

import org.junit.Before;
import org.junit.Test;
import org.omg.CORBA.Object;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

public class BaseClaimTest {
    private BaseClaim claim;

    @Before
    public void setUp() throws Exception {
        claim = new BaseClaim();
    }

    @Test
    public void shouldBeNull() throws Exception {
        assertThat(claim.isNull(), is(true));
    }

    @Test
    public void shouldGetAsBoolean() throws Exception {
        assertThat(claim.asBoolean(), is(nullValue()));
    }

    @Test
    public void shouldGetAsInt() throws Exception {
        assertThat(claim.asInt(), is(nullValue()));
    }

    @Test
    public void shouldGetAsDouble() throws Exception {
        assertThat(claim.asDouble(), is(nullValue()));
    }

    @Test
    public void shouldGetAsString() throws Exception {
        assertThat(claim.asString(), is(nullValue()));
    }

    @Test
    public void shouldGetAsDate() throws Exception {
        assertThat(claim.asDate(), is(nullValue()));
    }

    @Test
    public void shouldGetAsArray() throws Exception {
        assertThat(claim.asArray(Object.class), is(nullValue()));
    }

    @Test
    public void shouldGetAsList() throws Exception {
        assertThat(claim.asList(Object.class), is(nullValue()));
    }

}