package com.auth0.jwt.impl;

import com.auth0.jwt.interfaces.Claim;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.node.TextNode;
import org.hamcrest.collection.IsCollectionWithSize;
import org.hamcrest.core.IsIterableContaining;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.time.Instant;
import java.util.*;

import static com.auth0.jwt.impl.JWTParser.getDefaultObjectMapper;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class PayloadImplTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private PayloadImpl payload;
    private final Instant expiresAt = Instant.now().plusSeconds(10);
    private final Instant notBefore = Instant.now();
    private final Instant issuedAt = Instant.now();

    private ObjectReader objectReader;

    @Before
    public void setUp() {
        ObjectMapper mapper = getDefaultObjectMapper();
        objectReader = mapper.reader();

        Map<String, JsonNode> tree = new HashMap<>();
        tree.put("extraClaim", new TextNode("extraValue"));
        payload = new PayloadImpl("issuer", "subject", Collections.singletonList("audience"), expiresAt, notBefore, issuedAt, "jwtId", tree, objectReader);
    }

    @Test
    public void shouldHaveUnmodifiableTree() {
        exception.expect(UnsupportedOperationException.class);
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, new HashMap<>(), objectReader);
        payload.getTree().put("something", null);
    }

    @Test
    public void shouldHaveUnmodifiableAudience() {
        exception.expect(UnsupportedOperationException.class);
        PayloadImpl payload = new PayloadImpl(null, null, new ArrayList<>(), null, null, null, null, null, objectReader);
        payload.getAudience().add("something");
    }

    @Test
    public void shouldGetIssuer() {
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getIssuer(), is("issuer"));
    }

    @Test
    public void shouldGetNullIssuerIfMissing() {
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, null, objectReader);
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getIssuer(), is(nullValue()));
    }

    @Test
    public void shouldGetSubject() {
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getSubject(), is("subject"));
    }

    @Test
    public void shouldGetNullSubjectIfMissing() {
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, null, objectReader);
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getSubject(), is(nullValue()));
    }

    @Test
    public void shouldGetAudience() {
        assertThat(payload, is(notNullValue()));

        assertThat(payload.getAudience(), is(IsCollectionWithSize.hasSize(1)));
        assertThat(payload.getAudience(), is(IsIterableContaining.hasItems("audience")));
    }

    @Test
    public void shouldGetNullAudienceIfMissing() {
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, null, objectReader);
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getAudience(), is(nullValue()));
    }

    @Test
    public void shouldGetExpiresAt() {
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getExpiresAt(), is(Date.from(expiresAt)));
        assertThat(payload.getExpiresAtAsInstant(), is(expiresAt));
    }

    @Test
    public void shouldGetNullExpiresAtIfMissing() {
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, null, objectReader);
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getExpiresAt(), is(nullValue()));
        assertThat(payload.getExpiresAtAsInstant(), is(nullValue()));
    }

    @Test
    public void shouldGetNotBefore() {
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getNotBefore(), is(Date.from(notBefore)));
        assertThat(payload.getNotBeforeAsInstant(), is(notBefore));
    }

    @Test
    public void shouldGetNullNotBeforeIfMissing() {
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, null, objectReader);
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getNotBefore(), is(nullValue()));
        assertThat(payload.getNotBeforeAsInstant(), is(nullValue()));
    }

    @Test
    public void shouldGetIssuedAt() {
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getIssuedAt(), is(Date.from(issuedAt)));
        assertThat(payload.getIssuedAtAsInstant(), is(issuedAt));
    }

    @Test
    public void shouldGetNullIssuedAtIfMissing() {
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, null, objectReader);
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getIssuedAt(), is(nullValue()));
        assertThat(payload.getIssuedAtAsInstant(), is(nullValue()));
    }

    @Test
    public void shouldGetJWTId() {
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getId(), is("jwtId"));
    }

    @Test
    public void shouldGetNullJWTIdIfMissing() {
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, null, objectReader);
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getId(), is(nullValue()));
    }

    @Test
    public void shouldGetExtraClaim() {
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getClaim("extraClaim"), is(instanceOf(JsonNodeClaim.class)));
        assertThat(payload.getClaim("extraClaim").asString(), is("extraValue"));
    }

    @Test
    public void shouldGetNotNullExtraClaimIfMissing() {
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, null, objectReader);
        assertThat(payload, is(notNullValue()));
        assertThat(payload.getClaim("missing"), is(notNullValue()));
        assertThat(payload.getClaim("missing").isMissing(), is(true));
        assertThat(payload.getClaim("missing").isNull(), is(false));
    }

    @Test
    public void shouldGetClaims() {
        Map<String, JsonNode> tree = new HashMap<>();
        tree.put("extraClaim", new TextNode("extraValue"));
        tree.put("sub", new TextNode("auth0"));
        PayloadImpl payload = new PayloadImpl(null, null, null, null, null, null, null, tree, objectReader);
        assertThat(payload, is(notNullValue()));
        Map<String, Claim> claims = payload.getClaims();
        assertThat(claims, is(notNullValue()));

        assertThat(claims.get("extraClaim"), is(notNullValue()));
        assertThat(claims.get("sub"), is(notNullValue()));
    }

    @Test
    public void shouldNotAllowToModifyClaimsMap() {
        assertThat(payload, is(notNullValue()));
        Map<String, Claim> claims = payload.getClaims();
        assertThat(claims, is(notNullValue()));
        exception.expect(UnsupportedOperationException.class);
        claims.put("name", null);
    }
}