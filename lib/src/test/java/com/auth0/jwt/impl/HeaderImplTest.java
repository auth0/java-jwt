package com.auth0.jwt.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.TextNode;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.HashMap;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class HeaderImplTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @SuppressWarnings("Convert2Diamond")
    @Test
    public void shouldHaveUnmodifiableTree() throws Exception {
        exception.expect(UnsupportedOperationException.class);
        HeaderImpl header = new HeaderImpl(new HashMap<String, JsonNode>());
        header.getTree().put("something", null);
    }

    @Test
    public void shouldGetHS256Algorithm() throws Exception {
        JsonNode algNode = new TextNode("HS256");
        HashMap<String, JsonNode> tree = new HashMap<>();
        tree.put("alg", algNode);
        HeaderImpl header = new HeaderImpl(tree);

        assertThat(header, is(notNullValue()));
        assertThat(header.getAlgorithm(), is(notNullValue()));
        assertThat(header.getAlgorithm(), is("HS256"));
    }

    @Test
    public void shouldGetHS384Algorithm() throws Exception {
        JsonNode algNode = new TextNode("HS384");
        HashMap<String, JsonNode> tree = new HashMap<>();
        tree.put("alg", algNode);
        HeaderImpl header = new HeaderImpl(tree);

        assertThat(header, is(notNullValue()));
        assertThat(header.getAlgorithm(), is(notNullValue()));
        assertThat(header.getAlgorithm(), is("HS384"));
    }

    @Test
    public void shouldGetHS512Algorithm() throws Exception {
        JsonNode algNode = new TextNode("HS512");
        HashMap<String, JsonNode> tree = new HashMap<>();
        tree.put("alg", algNode);
        HeaderImpl header = new HeaderImpl(tree);

        assertThat(header, is(notNullValue()));
        assertThat(header.getAlgorithm(), is(notNullValue()));
        assertThat(header.getAlgorithm(), is("HS512"));
    }

    @Test
    public void shouldGetRS256Algorithm() throws Exception {
        JsonNode algNode = new TextNode("RS256");
        HashMap<String, JsonNode> tree = new HashMap<>();
        tree.put("alg", algNode);
        HeaderImpl header = new HeaderImpl(tree);

        assertThat(header, is(notNullValue()));
        assertThat(header.getAlgorithm(), is(notNullValue()));
        assertThat(header.getAlgorithm(), is("RS256"));
    }

    @Test
    public void shouldGetRS384Algorithm() throws Exception {
        JsonNode algNode = new TextNode("RS384");
        HashMap<String, JsonNode> tree = new HashMap<>();
        tree.put("alg", algNode);
        HeaderImpl header = new HeaderImpl(tree);

        assertThat(header, is(notNullValue()));
        assertThat(header.getAlgorithm(), is(notNullValue()));
        assertThat(header.getAlgorithm(), is("RS384"));
    }

    @Test
    public void shouldGetRS512Algorithm() throws Exception {
        JsonNode algNode = new TextNode("RS512");
        HashMap<String, JsonNode> tree = new HashMap<>();
        tree.put("alg", algNode);
        HeaderImpl header = new HeaderImpl(tree);

        assertThat(header, is(notNullValue()));
        assertThat(header.getAlgorithm(), is(notNullValue()));
        assertThat(header.getAlgorithm(), is("RS512"));
    }

    @Test
    public void shouldGetNoneAlgorithm() throws Exception {
        JsonNode algNode = new TextNode("none");
        HashMap<String, JsonNode> tree = new HashMap<>();
        tree.put("alg", algNode);
        HeaderImpl header = new HeaderImpl(tree);

        assertThat(header, is(notNullValue()));
        assertThat(header.getAlgorithm(), is(notNullValue()));
        assertThat(header.getAlgorithm(), is("none"));
    }

    @Test
    public void shouldGetNullAlgorithmIfMissing() throws Exception {
        HashMap<String, JsonNode> tree = new HashMap<>();
        HeaderImpl header = new HeaderImpl(tree);

        assertThat(header, is(notNullValue()));
        assertThat(header.getAlgorithm(), is(nullValue()));
    }

    @Test
    public void shouldGetType() throws Exception {
        JsonNode typNode = new TextNode("jwt");
        HashMap<String, JsonNode> tree = new HashMap<>();
        tree.put("typ", typNode);
        HeaderImpl header = new HeaderImpl(tree);

        assertThat(header, is(notNullValue()));
        assertThat(header.getType(), is(notNullValue()));
        assertThat(header.getType(), is("jwt"));
    }

    @Test
    public void shouldGetNullTypeIfMissing() throws Exception {
        HashMap<String, JsonNode> tree = new HashMap<>();
        HeaderImpl header = new HeaderImpl(tree);

        assertThat(header, is(notNullValue()));
        assertThat(header.getType(), is(nullValue()));
    }

    @Test
    public void shouldGetContentType() throws Exception {
        JsonNode ctyNode = new TextNode("jws");
        HashMap<String, JsonNode> tree = new HashMap<>();
        tree.put("cty", ctyNode);
        HeaderImpl header = new HeaderImpl(tree);

        assertThat(header, is(notNullValue()));
        assertThat(header.getContentType(), is(notNullValue()));
        assertThat(header.getContentType(), is("jws"));
    }

    @Test
    public void shouldGetNullContentTypeIfMissing() throws Exception {
        HashMap<String, JsonNode> tree = new HashMap<>();
        HeaderImpl header = new HeaderImpl(tree);

        assertThat(header, is(notNullValue()));
        assertThat(header.getContentType(), is(nullValue()));
    }
}