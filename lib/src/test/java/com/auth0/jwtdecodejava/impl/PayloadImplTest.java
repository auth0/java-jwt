package com.auth0.jwtdecodejava.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.TextNode;
import org.hamcrest.collection.IsArrayContaining;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class PayloadImplTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private PayloadImpl payload;
    private Date expiresAt;
    private Date notBefore;
    private Date issuedAt;

    @Before
    public void setUp() throws Exception {
        expiresAt = Mockito.mock(Date.class);
        notBefore = Mockito.mock(Date.class);
        issuedAt = Mockito.mock(Date.class);
        Map<String, JsonNode> tree = new HashMap<>();
        tree.put("extraClaim", new TextNode("extraValue"));
        payload = new PayloadImpl("issuer", "subject", new String[]{"audience"}, expiresAt, notBefore, issuedAt, "jwtId", tree);
    }

    @SuppressWarnings("Convert2Diamond")
    @Test
    public void shouldHaveUnmodifiableTree() throws Exception {
        exception.expect(UnsupportedOperationException.class);
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, new HashMap<String, JsonNode>());
        payload.getTree().put("something", null);
    }

    @Test
    public void shouldGetIssuer() throws Exception {
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getIssuer(), is("issuer"));
    }

    @Test
    public void shouldGetNullIssuerIfMissing() throws Exception {
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, null);
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getIssuer(), is(nullValue()));
    }

    @Test
    public void shouldGetSubject() throws Exception {
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getSubject(), is("subject"));
    }

    @Test
    public void shouldGetNullSubjectIfMissing() throws Exception {
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, null);
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getSubject(), is(nullValue()));
    }

    @Test
    public void shouldGetAudience() throws Exception {
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getAudience(), is(IsArrayContaining.hasItemInArray("audience")));
    }

    @Test
    public void shouldGetNullAudienceIfMissing() throws Exception {
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, null);
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getAudience(), is(nullValue()));
    }

    @Test
    public void shouldGetExpiresAt() throws Exception {
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getExpiresAt(), is(expiresAt));
    }

    @Test
    public void shouldGetNullExpiresAtIfMissing() throws Exception {
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, null);
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getExpiresAt(), is(nullValue()));
    }

    @Test
    public void shouldGetNotBefore() throws Exception {
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getNotBefore(), is(notBefore));
    }

    @Test
    public void shouldGetNullNotBeforeIfMissing() throws Exception {
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, null);
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getNotBefore(), is(nullValue()));
    }

    @Test
    public void shouldGetIssuedAt() throws Exception {
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getIssuedAt(), is(issuedAt));
    }

    @Test
    public void shouldGetNullIssuedAtIfMissing() throws Exception {
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, null);
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getIssuedAt(), is(nullValue()));
    }

    @Test
    public void shouldGetJWTId() throws Exception {
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getId(), is("jwtId"));
    }

    @Test
    public void shouldGetNullJWTIdIfMissing() throws Exception {
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, null);
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getId(), is(nullValue()));
    }

    @Test
    public void shouldGetExtraClaim() throws Exception {
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getClaim("extraClaim"), is(instanceOf(ClaimImpl.class)));
        assertThat(payload.getClaim("extraClaim").asString(), is("extraValue"));
    }

    @Test
    public void shouldGetNotNullExtraClaimIfMissing() throws Exception {
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, null);
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getClaim("missing"), is(notNullValue()));
        assertThat(payload.getClaim("missing"), is(instanceOf(BaseClaim.class)));
    }
}