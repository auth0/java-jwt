package com.auth0.jwt.impl;

import com.auth0.jwt.interfaces.Claim;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.TextNode;
import org.hamcrest.collection.IsCollectionWithSize;
import org.hamcrest.core.IsCollectionContaining;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;

import java.util.Collections;
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
        payload = new PayloadImpl("issuer", "subject", Collections.singletonList("audience"), expiresAt, notBefore, issuedAt, "jwtId", tree);
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

        assertThat(payload.getAudience(), is(IsCollectionWithSize.hasSize(1)));
        assertThat(payload.getAudience(), is(IsCollectionContaining.hasItems("audience")));
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
        assertThat(payload.getClaim("extraClaim"), is(instanceOf(JsonNodeClaim.class)));
        assertThat(payload.getClaim("extraClaim").asString(), is("extraValue"));
    }

    @Test
    public void shouldGetNotNullExtraClaimIfMissing() throws Exception {
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, null);
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getClaim("missing"), is(notNullValue()));
        assertThat(payload.getClaim("missing"), is(instanceOf(NullClaim.class)));
    }

    @Test
    public void shouldGetClaims() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        tree.put("extraClaim", new TextNode("extraValue"));
        tree.put("sub", new TextNode("auth0"));
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, tree);
        assertThat(payload, is(notNullValue()));
        Map<String, Claim> claims = payload.getClaims();
        assertThat(claims, is(notNullValue()));

        assertThat(claims.get("extraClaim"), is(notNullValue()));
        assertThat(claims.get("sub"), is(notNullValue()));
    }

    @Test
    public void shouldNotAllowToModifyClaimsMap() throws Exception {
        assertThat(payload, is(notNullValue()));
        Map<String, Claim> claims = payload.getClaims();
        assertThat(claims, is(notNullValue()));
        exception.expect(UnsupportedOperationException.class);
        claims.put("name", null);
    }
}