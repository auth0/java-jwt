package com.auth0.jwt;

import com.auth0.jwt.exceptions.JWTDecodeException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

public class SignUtilsTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldSplitToken() throws Exception {
        String token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc";
        String[] parts = SignUtils.splitToken(token);

        assertThat(parts, is(notNullValue()));
        assertThat(parts, is(arrayWithSize(3)));
        assertThat(parts[0], is("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"));
        assertThat(parts[1], is("eyJpc3MiOiJhdXRoMCJ9"));
        assertThat(parts[2], is("W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc"));
    }

    @Test
    public void shouldSplitTokenWithEmptySignature() throws Exception {
        String token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.";
        String[] parts = SignUtils.splitToken(token);

        assertThat(parts, is(notNullValue()));
        assertThat(parts, is(arrayWithSize(3)));
        assertThat(parts[0], is("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"));
        assertThat(parts[1], is("eyJpc3MiOiJhdXRoMCJ9"));
        assertThat(parts[2], is(isEmptyString()));
    }

    @Test
    public void shouldThrowOnSplitTokenWithMoreThan3Parts() throws Exception {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("The token was expected to have 3 parts, but got 4.");
        String token = "this.has.four.parts";
        SignUtils.splitToken(token);
    }

    @Test
    public void shouldThrowOnSplitTokenWithLessThan3Parts() throws Exception {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("The token was expected to have 3 parts, but got 2.");
        String token = "two.parts";
        SignUtils.splitToken(token);
    }

    @Test
    public void shouldDecodeBase64() throws Exception {
        String source = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        byte[] result = SignUtils.base64Decode(source);

        assertThat(result, is(notNullValue()));
        assertThat(result, is("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes()));
    }

    @Test
    public void shouldEncodeBase64() throws Exception {
        String source = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String result = SignUtils.base64Encode(source.getBytes());

        assertThat(result, is(notNullValue()));
        assertThat(result, is("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
    }

}