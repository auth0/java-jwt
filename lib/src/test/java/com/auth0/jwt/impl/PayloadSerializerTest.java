package com.auth0.jwt.impl;

import com.auth0.jwt.UserPojo;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import org.junit.Before;
import org.junit.Test;

import java.io.StringWriter;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

public class PayloadSerializerTest {
    private StringWriter writer;
    private PayloadSerializer serializer;
    private JsonGenerator jsonGenerator;
    private SerializerProvider serializerProvider;

    @Before
    public void setUp() throws Exception {
        writer = new StringWriter();
        serializer = new PayloadSerializer();
        jsonGenerator = new JsonFactory().createGenerator(writer);
        ObjectMapper mapper = new ObjectMapper();
        jsonGenerator.setCodec(mapper);
        serializerProvider = mapper.getSerializerProvider();
    }

    @SuppressWarnings("Convert2Diamond")
    @Test
    public void shouldSerializeEmptyMap() throws Exception {
        ClaimsHolder holder = new ClaimsHolder(new HashMap<String, Object>());
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{}")));
    }

    @Test
    public void shouldSerializeStringAudienceAsString() throws Exception {
        ClaimsHolder holder = holderFor("aud", "auth0");
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"aud\":\"auth0\"}")));
    }

    @Test
    public void shouldSerializeSingleItemAudienceAsArray() throws Exception {
        ClaimsHolder holder = holderFor("aud", new String[]{"auth0"});
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"aud\":\"auth0\"}")));
    }

    @Test
    public void shouldSerializeMultipleItemsAudienceAsArray() throws Exception {
        ClaimsHolder holder = holderFor("aud", new String[]{"auth0", "auth10"});
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"aud\":[\"auth0\",\"auth10\"]}")));
    }

    @Test
    public void shouldSkipSerializationOnEmptyAudience() throws Exception {
        ClaimsHolder holder = holderFor("aud", new String[0]);
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{}")));
    }

    @Test
    public void shouldSerializeNotBeforeInstantInSeconds() throws Exception {
        ClaimsHolder holder = holderFor("nbf", Instant.ofEpochMilli(1478874000));
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"nbf\":1478874}")));
    }

    @Test
    public void shouldSerializeIssuedAtInstantInSeconds() throws Exception {
        ClaimsHolder holder = holderFor("iat", Instant.ofEpochMilli(1478874000));
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"iat\":1478874}")));
    }

    @Test
    public void shouldSerializeExpiresAtInstantInSeconds() throws Exception {
        ClaimsHolder holder = holderFor("exp", Instant.ofEpochMilli(1478874000));
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"exp\":1478874}")));
    }

    @Test
    public void shouldSerializeCustomInstantInSeconds() throws Exception {
        ClaimsHolder holder = holderFor("birthdate", Instant.ofEpochMilli(1478874000));
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"birthdate\":1478874}")));
    }

    @Test
    public void shouldSerializeInstantsUsingLong() throws Exception {
        long secs = Integer.MAX_VALUE + 10000L;
        Instant instant = Instant.ofEpochSecond(secs);
        Map<String, Object> claims = new HashMap<String, Object>();
        claims.put("iat", instant);
        claims.put("nbf", instant);
        claims.put("exp", instant);
        claims.put("ctm", instant);
        ClaimsHolder holder = new ClaimsHolder(claims);
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        String json = writer.toString();
        assertThat(json, containsString("\"iat\":2147493647"));
        assertThat(json, containsString("\"nbf\":2147493647"));
        assertThat(json, containsString("\"exp\":2147493647"));
        assertThat(json, containsString("\"ctm\":2147493647"));
    }

    @Test
    public void shouldSerializeStrings() throws Exception {
        ClaimsHolder holder = holderFor("name", "Auth0 Inc");
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"name\":\"Auth0 Inc\"}")));
    }

    @Test
    public void shouldSerializeIntegers() throws Exception {
        ClaimsHolder holder = holderFor("number", 12345);
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"number\":12345}")));
    }

    @Test
    public void shouldSerializeDoubles() throws Exception {
        ClaimsHolder holder = holderFor("fraction", 23.45);
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"fraction\":23.45}")));
    }

    @Test
    public void shouldSerializeBooleans() throws Exception {
        ClaimsHolder holder = holderFor("pro", true);
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"pro\":true}")));
    }

    @Test
    public void shouldSerializeNulls() throws Exception {
        ClaimsHolder holder = holderFor("id", null);
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"id\":null}")));
    }

    @Test
    public void shouldSerializeCustomArrayOfObject() throws Exception {
        UserPojo user1 = new UserPojo("Michael", 1);
        UserPojo user2 = new UserPojo("Lucas", 2);
        ClaimsHolder holder = holderFor("users", new UserPojo[]{user1, user2});
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"users\":[{\"name\":\"Michael\",\"id\":1},{\"name\":\"Lucas\",\"id\":2}]}")));
    }

    @Test
    public void shouldSerializeCustomListOfObject() throws Exception {
        UserPojo user1 = new UserPojo("Michael", 1);
        UserPojo user2 = new UserPojo("Lucas", 2);
        ClaimsHolder holder = holderFor("users", Arrays.asList(user1, user2));
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"users\":[{\"name\":\"Michael\",\"id\":1},{\"name\":\"Lucas\",\"id\":2}]}")));
    }

    @Test
    public void shouldSerializeCustomObject() throws Exception {
        UserPojo user = new UserPojo("Michael", 1);
        ClaimsHolder holder = holderFor("users", user);
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"users\":{\"name\":\"Michael\",\"id\":1}}")));
    }

    @SuppressWarnings("Convert2Diamond")
    private ClaimsHolder holderFor(String key, Object value) {
        Map<String, Object> map = new HashMap<String, Object>();
        map.put(key, value);
        return new ClaimsHolder(map);
    }
}
