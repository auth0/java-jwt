package com.auth0.jwtdecodejava.impl;

import com.auth0.jwtdecodejava.exceptions.JWTDecodeException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.*;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.*;
import static org.hamcrest.collection.IsArrayContainingInOrder.arrayContaining;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PayloadDeserializerTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    private PayloadDeserializer deserializer;

    @Before
    public void setUp() throws Exception {
        deserializer = new PayloadDeserializer();
    }

    @Test
    public void shouldThrowOnNullTree() throws Exception {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("Parsing the Payload's JSON resulted on a Null map");

        JsonParser parser = mock(JsonParser.class);
        ObjectCodec codec = mock(ObjectCodec.class);
        DeserializationContext context = mock(DeserializationContext.class);

        when(codec.readValue(eq(parser), any(TypeReference.class))).thenReturn(null);
        when(parser.getCodec()).thenReturn(codec);

        deserializer.deserialize(parser, context);
    }

    @Test
    public void shouldThrowWhenParsingArrayWithObjectValue() throws Exception {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("Couldn't map the Claim's array contents to String");

        ObjectMapper mapper = new ObjectMapper();//mock(ObjectMapper.class);
        JsonNode jsonNode = mapper.readTree("{\"some\" : \"random\", \"properties\" : \"inside\"}");
        Map<String, JsonNode> tree = new HashMap<>();
        List<JsonNode> subNodes = new ArrayList<>();
        subNodes.add(jsonNode);
        ArrayNode arrNode = new ArrayNode(JsonNodeFactory.instance, subNodes);
        tree.put("key", arrNode);

        deserializer.getStringOrArray(tree, "key");
    }

    @Test
    public void shouldGetStringArrayWhenParsingArrayNode() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        List<JsonNode> subNodes = new ArrayList<>();
        TextNode textNode1 = new TextNode("one");
        TextNode textNode2 = new TextNode("two");
        subNodes.add(textNode1);
        subNodes.add(textNode2);
        ArrayNode arrNode = new ArrayNode(JsonNodeFactory.instance, subNodes);
        tree.put("key", arrNode);

        String[] values = deserializer.getStringOrArray(tree, "key");
        assertThat(values, is(notNullValue()));
        assertThat(values, is(arrayWithSize(2)));
        assertThat(values, is(arrayContaining("one", "two")));
    }

    @Test
    public void shouldGetStringArrayWhenParsingTextNode() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        TextNode textNode = new TextNode("something");
        tree.put("key", textNode);

        String[] values = deserializer.getStringOrArray(tree, "key");
        assertThat(values, is(notNullValue()));
        assertThat(values, is(arrayWithSize(1)));
        assertThat(values, is(arrayContaining("something")));
    }

    @Test
    public void shouldGetNullArrayWhenParsingNullNode() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        NullNode node = NullNode.getInstance();
        tree.put("key", node);

        String[] values = deserializer.getStringOrArray(tree, "key");
        assertThat(values, is(nullValue()));
    }

    @Test
    public void shouldGetNullArrayWhenParsingNullNodeValue() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        tree.put("key", null);

        String[] values = deserializer.getStringOrArray(tree, "key");
        assertThat(values, is(nullValue()));
    }

    @Test
    public void shouldGetNullArrayWhenParsingNonArrayOrTextNode() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        IntNode node = new IntNode(456789);
        tree.put("key", node);

        String[] values = deserializer.getStringOrArray(tree, "key");
        assertThat(values, is(nullValue()));
    }

}