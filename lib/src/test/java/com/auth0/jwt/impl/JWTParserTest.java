package com.auth0.jwt.impl;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Header;
import com.auth0.jwt.interfaces.Payload;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static com.auth0.jwt.impl.JWTParser.getDefaultObjectMapper;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class JWTParserTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();
    private JWTParser parser;

    @Before
    public void setUp() {
        parser = new JWTParser();
    }

    @Test
    public void shouldGetDefaultObjectMapper() {
        ObjectMapper mapper = getDefaultObjectMapper();
        assertThat(mapper, is(notNullValue()));
        assertThat(mapper, is(instanceOf(ObjectMapper.class)));
        assertThat(mapper.isEnabled(SerializationFeature.FAIL_ON_EMPTY_BEANS), is(false));
    }

    @Test
    public void shouldAddDeserializers() {
        ObjectMapper mapper = mock(ObjectMapper.class);
        new JWTParser(mapper);
        verify(mapper).registerModule(any(Module.class));
    }

    @Test
    public void shouldParsePayload() throws Exception {
        ObjectMapper mapper = mock(ObjectMapper.class);
        ObjectReader reader = mock(ObjectReader.class);
        when(mapper.readerFor(Payload.class)).thenReturn(reader);
        JWTParser parser = new JWTParser(mapper);
        parser.parsePayload("{}");

        verify(reader).readValue("{}");
    }

    @Test
    public void shouldThrowOnInvalidPayload() {
        String jsonPayload = "{{";
        exception.expect(JWTDecodeException.class);
        exception.expectMessage(String.format("The string '%s' doesn't have a valid JSON format.", jsonPayload));
        Payload payload = parser.parsePayload(jsonPayload);
        assertThat(payload, is(nullValue()));
    }

    @Test
    public void shouldParseHeader() throws Exception {
        ObjectMapper mapper = mock(ObjectMapper.class);
        ObjectReader reader = mock(ObjectReader.class);
        when(mapper.readerFor(Header.class)).thenReturn(reader);
        JWTParser parser = new JWTParser(mapper);
        parser.parseHeader("{}");

        verify(reader).readValue("{}");
    }

    @Test
    public void shouldThrowOnInvalidHeader() {
        String jsonHeader = "}}";
        exception.expect(JWTDecodeException.class);
        exception.expectMessage(String.format("The string '%s' doesn't have a valid JSON format.", jsonHeader));
        Header header = parser.parseHeader(jsonHeader);
        assertThat(header, is(nullValue()));
    }

    @Test
    public void shouldThrowWhenConvertingHeaderIfNullJson() {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("The string 'null' doesn't have a valid JSON format.");
        parser.parseHeader(null);
    }

    @Test
    public void shouldThrowWhenConvertingHeaderFromInvalidJson() {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("The string '}{' doesn't have a valid JSON format.");
        parser.parseHeader("}{");
    }

    @Test
    public void shouldThrowWhenConvertingPayloadIfNullJson() {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("The string 'null' doesn't have a valid JSON format.");
        parser.parsePayload(null);
    }

    @Test
    public void shouldThrowWhenConvertingPayloadFromInvalidJson() {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("The string '}{' doesn't have a valid JSON format.");
        parser.parsePayload("}{");
    }
}
