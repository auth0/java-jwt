package com.auth0.jwt.impl;

import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.NullNode;
import org.hamcrest.collection.IsMapContaining;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import tools.jackson.databind.node.StringNode;

import java.util.HashMap;
import java.util.Map;

import static com.auth0.jwt.impl.JWTParser.getDefaultObjectMapper;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class BasicHeaderTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    
    private final DeserializationContext context = getDefaultObjectMapper()._deserializationContext();

    @SuppressWarnings("Convert2Diamond")
    @Test
    public void shouldHaveUnmodifiableTreeWhenInstantiatedWithNonNullTree() {
        exception.expect(UnsupportedOperationException.class);
        BasicHeader header = new BasicHeader(null, null, null, null, new HashMap<String, JsonNode>(), context);
        header.getTree().put("something", null);
    }

    @Test
    public void shouldHaveUnmodifiableTreeWhenInstantiatedWithNullTree() {
        exception.expect(UnsupportedOperationException.class);
        BasicHeader header = new BasicHeader(null, null, null, null, null, context);
        header.getTree().put("something", null);
    }

    @Test
    public void shouldHaveTree() {
        HashMap<String, JsonNode> map = new HashMap<>();
        JsonNode node = NullNode.getInstance();
        map.put("key", node);
        BasicHeader header = new BasicHeader(null, null, null, null, map, context);

        assertThat(header.getTree(), is(notNullValue()));
        assertThat(header.getTree(), is(IsMapContaining.hasEntry("key", node)));
    }

    @Test
    public void shouldGetAlgorithm() {
        BasicHeader header = new BasicHeader("HS256", null, null, null, null, context);

        assertThat(header, is(notNullValue()));
        assertThat(header.getAlgorithm(), is(notNullValue()));
        assertThat(header.getAlgorithm(), is("HS256"));
    }

    @Test
    public void shouldGetNullAlgorithmIfMissing() {
        BasicHeader header = new BasicHeader(null, null, null, null, null, context);

        assertThat(header, is(notNullValue()));
        assertThat(header.getAlgorithm(), is(nullValue()));
    }

    @Test
    public void shouldGetType() {
        BasicHeader header = new BasicHeader(null, "jwt", null, null, null, context);

        assertThat(header, is(notNullValue()));
        assertThat(header.getType(), is(notNullValue()));
        assertThat(header.getType(), is("jwt"));
    }

    @Test
    public void shouldGetNullTypeIfMissing() {
        BasicHeader header = new BasicHeader(null, null, null, null, null, context);

        assertThat(header, is(notNullValue()));
        assertThat(header.getType(), is(nullValue()));
    }

    @Test
    public void shouldGetContentType() {
        BasicHeader header = new BasicHeader(null, null, "content", null, null, context);

        assertThat(header, is(notNullValue()));
        assertThat(header.getContentType(), is(notNullValue()));
        assertThat(header.getContentType(), is("content"));
    }

    @Test
    public void shouldGetNullContentTypeIfMissing() {
        BasicHeader header = new BasicHeader(null, null, null, null, null, context);

        assertThat(header, is(notNullValue()));
        assertThat(header.getContentType(), is(nullValue()));
    }

    @Test
    public void shouldGetKeyId() {
        BasicHeader header = new BasicHeader(null, null, null, "key", null, context);

        assertThat(header, is(notNullValue()));
        assertThat(header.getKeyId(), is(notNullValue()));
        assertThat(header.getKeyId(), is("key"));
    }

    @Test
    public void shouldGetNullKeyIdIfMissing() {
        BasicHeader header = new BasicHeader(null, null, null, null, null, context);

        assertThat(header, is(notNullValue()));
        assertThat(header.getKeyId(), is(nullValue()));
    }

    @Test
    public void shouldGetExtraClaim() {
        Map<String, JsonNode> tree = new HashMap<>();
        tree.put("extraClaim", new StringNode("extraValue"));
        BasicHeader header = new BasicHeader(null, null, null, null, tree, context);

        assertThat(header, is(notNullValue()));
        assertThat(header.getHeaderClaim("extraClaim"), is(instanceOf(JsonNodeClaim.class)));
        assertThat(header.getHeaderClaim("extraClaim").asString(), is("extraValue"));
    }

    @Test
    public void shouldGetNotNullExtraClaimIfMissing() {
        Map<String, JsonNode> tree = new HashMap<>();
        BasicHeader header = new BasicHeader(null, null, null, null, tree, context);

        assertThat(header, is(notNullValue()));
        assertThat(header.getHeaderClaim("missing"), is(notNullValue()));
        assertThat(header.getHeaderClaim("missing").isMissing(), is(true));
        assertThat(header.getHeaderClaim("missing").isNull(), is(false));
    }
}