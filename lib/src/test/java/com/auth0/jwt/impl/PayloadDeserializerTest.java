package com.auth0.jwt.impl;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Payload;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.*;
import org.hamcrest.collection.IsCollectionWithSize;
import org.hamcrest.collection.IsEmptyCollection;
import org.hamcrest.core.IsCollectionContaining;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.StringReader;
import java.util.*;

import static org.hamcrest.Matchers.*;
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

        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode = mapper.readTree("{\"some\" : \"random\", \"properties\" : \"inside\"}");
        Map<String, JsonNode> tree = new HashMap<>();
        List<JsonNode> subNodes = new ArrayList<>();
        subNodes.add(jsonNode);
        ArrayNode arrNode = new ArrayNode(JsonNodeFactory.instance, subNodes);
        tree.put("key", arrNode);

        deserializer.getStringOrArray(tree, "key");
    }

    @Test
    public void shouldRemoveKnownPublicClaimsFromTree() throws Exception {
        String payloadJSON = "{\n" +
                "  \"iss\": \"auth0\",\n" +
                "  \"sub\": \"emails\",\n" +
                "  \"aud\": \"users\",\n" +
                "  \"iat\": 10101010,\n" +
                "  \"exp\": 11111111,\n" +
                "  \"nbf\": 10101011,\n" +
                "  \"jti\": \"idid\",\n" +
                "  \"roles\":\"admin\" \n" +
                "}";
        StringReader reader = new StringReader(payloadJSON);
        JsonParser jsonParser = new JsonFactory().createParser(reader);
        ObjectMapper mapper = new ObjectMapper();
        jsonParser.setCodec(mapper);

        Payload payload = deserializer.deserialize(jsonParser, mapper.getDeserializationContext());

        assertThat(payload, is(notNullValue()));
        assertThat(payload.getIssuer(), is("auth0"));
        assertThat(payload.getSubject(), is("emails"));
        assertThat(payload.getAudience(), is(IsCollectionContaining.hasItem("users")));
        assertThat(payload.getIssuedAt().getTime(), is(10101010L * 1000));
        assertThat(payload.getExpiresAt().getTime(), is(11111111L * 1000));
        assertThat(payload.getNotBefore().getTime(), is(10101011L * 1000));
        assertThat(payload.getId(), is("idid"));

        assertThat(payload.getClaim("roles").asString(), is("admin"));
        assertThat(payload.getClaim("iss").isNull(), is(true));
        assertThat(payload.getClaim("sub").isNull(), is(true));
        assertThat(payload.getClaim("aud").isNull(), is(true));
        assertThat(payload.getClaim("iat").isNull(), is(true));
        assertThat(payload.getClaim("exp").isNull(), is(true));
        assertThat(payload.getClaim("nbf").isNull(), is(true));
        assertThat(payload.getClaim("jti").isNull(), is(true));

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

        List<String> values = deserializer.getStringOrArray(tree, "key");
        assertThat(values, is(notNullValue()));
        assertThat(values, is(IsCollectionWithSize.hasSize(2)));
        assertThat(values, is(IsCollectionContaining.hasItems("one", "two")));
    }

    @Test
    public void shouldGetStringArrayWhenParsingTextNode() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        TextNode textNode = new TextNode("something");
        tree.put("key", textNode);

        List<String> values = deserializer.getStringOrArray(tree, "key");
        assertThat(values, is(notNullValue()));
        assertThat(values, is(IsCollectionWithSize.hasSize(1)));
        assertThat(values, is(IsCollectionContaining.hasItems("something")));
    }

    @Test
    public void shouldGetEmptyStringArrayWhenParsingEmptyTextNode() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        TextNode textNode = new TextNode("");
        tree.put("key", textNode);

        List<String> values = deserializer.getStringOrArray(tree, "key");
        assertThat(values, is(notNullValue()));
        assertThat(values, is(IsEmptyCollection.empty()));
    }

    @Test
    public void shouldGetNullArrayWhenParsingNullNode() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        NullNode node = NullNode.getInstance();
        tree.put("key", node);

        List<String> values = deserializer.getStringOrArray(tree, "key");
        assertThat(values, is(nullValue()));
    }

    @Test
    public void shouldGetNullArrayWhenParsingNullNodeValue() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        tree.put("key", null);

        List<String> values = deserializer.getStringOrArray(tree, "key");
        assertThat(values, is(nullValue()));
    }

    @Test
    public void shouldGetNullArrayWhenParsingNonArrayOrTextNode() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        IntNode node = new IntNode(456789);
        tree.put("key", node);

        List<String> values = deserializer.getStringOrArray(tree, "key");
        assertThat(values, is(nullValue()));
    }


    @Test
    public void shouldGetNullDateWhenParsingNullNode() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        NullNode node = NullNode.getInstance();
        tree.put("key", node);

        Date date = deserializer.getDateFromSeconds(tree, "key");
        assertThat(date, is(nullValue()));
    }

    @Test
    public void shouldGetNullDateWhenParsingNull() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        tree.put("key", null);

        Date date = deserializer.getDateFromSeconds(tree, "key");
        assertThat(date, is(nullValue()));
    }

    @Test
    public void shouldGetNullDateWhenParsingNonNumericNode() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        TextNode node = new TextNode("123456789");
        tree.put("key", node);

        Date date = deserializer.getDateFromSeconds(tree, "key");
        assertThat(date, is(nullValue()));
    }

    @Test
    public void shouldGetDateWhenParsingNumericNode() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        long seconds = 1478627949 / 1000;
        LongNode node = new LongNode(seconds);
        tree.put("key", node);

        Date date = deserializer.getDateFromSeconds(tree, "key");
        assertThat(date, is(notNullValue()));
        assertThat(date.getTime(), is(seconds * 1000));
    }

    @Test
    public void shouldGetNullStringWhenParsingNullNode() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        NullNode node = NullNode.getInstance();
        tree.put("key", node);

        String text = deserializer.getString(tree, "key");
        assertThat(text, is(nullValue()));
    }

    @Test
    public void shouldGetNullStringWhenParsingNull() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        tree.put("key", null);

        String text = deserializer.getString(tree, "key");
        assertThat(text, is(nullValue()));
    }

    @Test
    public void shouldGetStringWhenParsingTextNode() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        TextNode node = new TextNode("something here");
        tree.put("key", node);

        String text = deserializer.getString(tree, "key");
        assertThat(text, is(notNullValue()));
        assertThat(text, is("something here"));
    }

}