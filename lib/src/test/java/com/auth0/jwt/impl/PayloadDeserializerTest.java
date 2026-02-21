package com.auth0.jwt.impl;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Payload;
import tools.jackson.core.JsonParser;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.*;
import org.hamcrest.collection.IsCollectionWithSize;
import org.hamcrest.core.IsIterableContaining;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import tools.jackson.databind.node.StringNode;

import java.io.StringReader;
import java.time.Instant;
import java.util.*;

import static org.hamcrest.Matchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PayloadDeserializerTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    private PayloadDeserializer deserializer;

    private ObjectMapper objectMapper;

    @Before
    public void setUp() {
        objectMapper = new ObjectMapper();
        deserializer = new PayloadDeserializer();
    }


    @Test
    public void shouldThrowOnNullTree() {
        Throwable exception = assertThrows(JWTDecodeException.class, () -> {

            JsonParser parser = mock(JsonParser.class);
            DeserializationContext context = mock(DeserializationContext.class);

            when(context.readValue(eq(parser), any(TypeReference.class))).thenReturn(null);

            deserializer.deserialize(parser, context);
        });
        assertThat(exception.getMessage(), containsString("Parsing the Payload's JSON resulted on a Null map"));
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

        deserializer.getStringOrArray(objectMapper._deserializationContext(), tree, "key");
    }

    @Test
    public void shouldNotRemoveKnownPublicClaimsFromTree() throws Exception {
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
        ObjectMapper mapper = new ObjectMapper();
        JsonParser jsonParser = mapper.createParser(reader);
        DeserializationContext ctx = mapper._deserializationContext();

        Payload payload = deserializer.deserialize(jsonParser, ctx);

        assertThat(payload, is(notNullValue()));
        assertThat(payload.getIssuer(), is("auth0"));
        assertThat(payload.getSubject(), is("emails"));
        assertThat(payload.getAudience(), is(IsIterableContaining.hasItem("users")));
        assertThat(payload.getIssuedAt().getTime(), is(10101010L * 1000));
        assertThat(payload.getExpiresAt().getTime(), is(11111111L * 1000));
        assertThat(payload.getNotBefore().getTime(), is(10101011L * 1000));
        assertThat(payload.getIssuedAtAsInstant().getEpochSecond(), is(10101010L));
        assertThat(payload.getExpiresAtAsInstant().getEpochSecond(), is(11111111L));
        assertThat(payload.getNotBeforeAsInstant().getEpochSecond(), is(10101011L));
        assertThat(payload.getId(), is("idid"));

        assertThat(payload.getClaim("roles").asString(), is("admin"));
        assertThat(payload.getClaim("iss").asString(), is("auth0"));
        assertThat(payload.getClaim("sub").asString(), is("emails"));
        assertThat(payload.getClaim("aud").asString(), is("users"));
        assertThat(payload.getClaim("iat").asDouble(), is(10101010D));
        assertThat(payload.getClaim("exp").asDouble(), is(11111111D));
        assertThat(payload.getClaim("nbf").asDouble(), is(10101011D));
        assertThat(payload.getClaim("jti").asString(), is("idid"));
    }

    @Test
    public void shouldGetStringArrayWhenParsingArrayNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        List<JsonNode> subNodes = new ArrayList<>();
        StringNode textNode1 = new StringNode("one");
        StringNode textNode2 = new StringNode("two");
        subNodes.add(textNode1);
        subNodes.add(textNode2);
        ArrayNode arrNode = new ArrayNode(JsonNodeFactory.instance, subNodes);
        tree.put("key", arrNode);

        List<String> values = deserializer.getStringOrArray(objectMapper._deserializationContext(), tree, "key");
        assertThat(values, is(notNullValue()));
        assertThat(values, is(IsCollectionWithSize.hasSize(2)));
        assertThat(values, is(IsIterableContaining.hasItems("one", "two")));
    }

    @Test
    public void shouldGetStringArrayWhenParsingTextNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        StringNode textNode = new StringNode("something");
        tree.put("key", textNode);

        List<String> values = deserializer.getStringOrArray(objectMapper._deserializationContext(), tree, "key");
        assertThat(values, is(notNullValue()));
        assertThat(values, is(IsCollectionWithSize.hasSize(1)));
        assertThat(values, is(IsIterableContaining.hasItems("something")));
    }

    @Test
    public void shouldGetEmptyStringInArrayWhenParsingEmptyTextNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        StringNode textNode = new StringNode("");
        tree.put("key", textNode);

        List<String> values = deserializer.getStringOrArray(objectMapper._deserializationContext(), tree, "key");
        assertThat(values, is(notNullValue()));
        assertThat(values, is(IsIterableContaining.hasItem("")));
    }

    @Test
    public void shouldGetNullArrayWhenParsingNullNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        NullNode node = NullNode.getInstance();
        tree.put("key", node);

        List<String> values = deserializer.getStringOrArray(objectMapper._deserializationContext(), tree, "key");
        assertThat(values, is(nullValue()));
    }

    @Test
    public void shouldGetNullArrayWhenParsingNullNodeValue() {
        Map<String, JsonNode> tree = new HashMap<>();
        tree.put("key", null);

        List<String> values = deserializer.getStringOrArray(objectMapper._deserializationContext(), tree, "key");
        assertThat(values, is(nullValue()));
    }

    @Test
    public void shouldGetNullArrayWhenParsingNonArrayOrTextNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        IntNode node = new IntNode(456789);
        tree.put("key", node);

        List<String> values = deserializer.getStringOrArray(objectMapper._deserializationContext(), tree, "key");
        assertThat(values, is(nullValue()));
    }

    @Test
    public void shouldGetNullInstantWhenParsingNullNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        NullNode node = NullNode.getInstance();
        tree.put("key", node);

        Instant instant = deserializer.getInstantFromSeconds(tree, "key");
        assertThat(instant, is(nullValue()));
    }

    @Test
    public void shouldGetNullInstantWhenParsingNull() {
        Map<String, JsonNode> tree = new HashMap<>();
        tree.put("key", null);

        Instant instant  = deserializer.getInstantFromSeconds(tree, "key");
        assertThat(instant, is(nullValue()));
    }

    @Test
    public void shouldThrowWhenParsingNonNumericNode() {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("The claim 'key' contained a non-numeric date value.");

        Map<String, JsonNode> tree = new HashMap<>();
        StringNode node = new StringNode("123456789");
        tree.put("key", node);

        deserializer.getInstantFromSeconds(tree, "key");
    }

    @Test
    public void shouldGetInstantWhenParsingNumericNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        long seconds = 1478627949 / 1000;
        LongNode node = new LongNode(seconds);
        tree.put("key", node);

        Instant instant = deserializer.getInstantFromSeconds(tree, "key");
        assertThat(instant, is(notNullValue()));
        assertThat(instant.toEpochMilli(), is(seconds * 1000));
    }


    @Test
    public void shouldGetLargeInstantWhenParsingNumericNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        long seconds = Integer.MAX_VALUE + 10000L;
        LongNode node = new LongNode(seconds);
        tree.put("key", node);

        Instant instant = deserializer.getInstantFromSeconds(tree, "key");
        assertThat(instant, is(notNullValue()));
        assertThat(instant.toEpochMilli(), is(seconds * 1000));
        assertThat(instant.toEpochMilli(), is(2147493647L * 1000));
    }

    @Test
    public void shouldGetNullStringWhenParsingNullNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        NullNode node = NullNode.getInstance();
        tree.put("key", node);

        String text = deserializer.getString(tree, "key");
        assertThat(text, is(nullValue()));
    }

    @Test
    public void shouldGetNullStringWhenParsingNull() {
        Map<String, JsonNode> tree = new HashMap<>();
        tree.put("key", null);

        String text = deserializer.getString(tree, "key");
        assertThat(text, is(nullValue()));
    }

    @Test
    public void shouldGetStringWhenParsingTextNode() {
        Map<String, JsonNode> tree = new HashMap<>();
        StringNode node = new StringNode("something here");
        tree.put("key", node);

        String text = deserializer.getString(tree, "key");
        assertThat(text, is(notNullValue()));
        assertThat(text, is("something here"));
    }

}