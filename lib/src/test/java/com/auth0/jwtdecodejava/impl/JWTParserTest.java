package com.auth0.jwtdecodejava.impl;

import com.auth0.jwtdecodejava.interfaces.Claim;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.junit.Before;
import org.junit.Test;

import static com.auth0.jwtdecodejava.impl.JWTParser.getDefaultObjectMapper;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class JWTParserTest {

    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void shouldGetDefaultObjectMapper() throws Exception {
        ObjectMapper mapper = getDefaultObjectMapper();
        assertThat(mapper, is(notNullValue()));
        assertThat(mapper, is(instanceOf(ObjectMapper.class)));
        assertThat(mapper.isEnabled(SerializationFeature.FAIL_ON_EMPTY_BEANS), is(false));
    }

    @Test
    public void extractClaim() throws Exception {

    }

    @Test
    public void shouldGenerateNullClaimFromNullNode() throws Exception {
        Claim claim = null;
        assertThat(claim, is(notNullValue()));
        assertThat(claim, is(instanceOf(NullClaim.class)));
    }

    @Test
    public void shouldGenerateMissingClaimFromMissingNode() throws Exception {

    }

    @Test
    public void shouldGenerateValidClaimFromJsonNode() throws Exception {

    }
}