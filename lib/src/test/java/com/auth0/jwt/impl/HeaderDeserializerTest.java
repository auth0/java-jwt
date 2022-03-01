package com.auth0.jwt.impl;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Header;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.TextNode;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class HeaderDeserializerTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    private HeaderDeserializer deserializer;
    private ObjectReader objectReader = new ObjectMapper().reader();

    @Before
    public void setUp() throws Exception {
        deserializer = new HeaderDeserializer(objectReader);
    }

    @Test
    public void shouldThrowOnNullTree() throws Exception {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("Parsing the Header's JSON resulted on a Null map");

        JsonDeserializer deserializer = new HeaderDeserializer(objectReader);
        JsonParser parser = mock(JsonParser.class);
        ObjectCodec codec = mock(ObjectCodec.class);
        DeserializationContext context = mock(DeserializationContext.class);

        when(codec.readValue(eq(parser), any(TypeReference.class))).thenReturn(null);
        when(parser.getCodec()).thenReturn(codec);

        deserializer.deserialize(parser, context);
    }


    @Test
    public void shouldNotRemoveKnownPublicClaimsFromTree() throws Exception {
        String headerJSON = "{\n" +
                "  \"alg\": \"HS256\",\n" +
                "  \"typ\": \"jws\",\n" +
                "  \"cty\": \"content\",\n" +
                "  \"kid\": \"key\",\n" +
                "  \"roles\": \"admin\"\n" +
                "}";
        StringReader reader = new StringReader(headerJSON);
        JsonParser jsonParser = new JsonFactory().createParser(reader);
        ObjectMapper mapper = new ObjectMapper();
        jsonParser.setCodec(mapper);

        Header header = deserializer.deserialize(jsonParser, mapper.getDeserializationContext());

        assertThat(header, is(notNullValue()));
        assertThat(header.getAlgorithm(), is("HS256"));
        assertThat(header.getType(), is("jws"));
        assertThat(header.getContentType(), is("content"));
        assertThat(header.getKeyId(), is("key"));

        assertThat(header.getHeaderClaim("roles").asString(), is("admin"));
        assertThat(header.getHeaderClaim("alg").asString(), is("HS256"));
        assertThat(header.getHeaderClaim("typ").asString(), is("jws"));
        assertThat(header.getHeaderClaim("cty").asString(), is("content"));
        assertThat(header.getHeaderClaim("kid").asString(), is("key"));
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