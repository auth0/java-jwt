package com.auth0.jwtdecodejava;

import com.auth0.jwtdecodejava.enums.Algorithm;
import com.auth0.jwtdecodejava.exceptions.JWTException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

public class UtilsTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldSplitToken() throws Exception {
        String token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc";
        String[] parts = Utils.splitToken(token);

        assertThat(parts, is(notNullValue()));
        assertThat(parts, is(arrayWithSize(3)));
        assertThat(parts[0], is("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"));
        assertThat(parts[1], is("eyJpc3MiOiJhdXRoMCJ9"));
        assertThat(parts[2], is("W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc"));
    }

    @Test
    public void shouldSplitTokenWithEmptySignature() throws Exception {
        String token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.";
        String[] parts = Utils.splitToken(token);

        assertThat(parts, is(notNullValue()));
        assertThat(parts, is(arrayWithSize(3)));
        assertThat(parts[0], is("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"));
        assertThat(parts[1], is("eyJpc3MiOiJhdXRoMCJ9"));
        assertThat(parts[2], is(isEmptyString()));
    }

    @Test
    public void shouldThrowOnSplitTokenWithMoreThan3Parts() throws Exception {
        exception.expect(JWTException.class);
        exception.expectMessage("The token was expected to have 3 parts, but got 4.");
        String token = "this.has.four.parts";
        Utils.splitToken(token);
    }

    @Test
    public void shouldThrowOnSplitTokenWithLessThan3Parts() throws Exception {
        exception.expect(JWTException.class);
        exception.expectMessage("The token was expected to have 3 parts, but got 2.");
        String token = "two.parts";
        Utils.splitToken(token);
    }

    @Test
    public void shouldDecodeBase64() throws Exception {
        String source = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        String result = Utils.base64Decode(source);

        assertThat(result, is(notNullValue()));
        assertThat(result, is("{\"alg\":\"HS256\",\"typ\":\"JWT\"}"));
    }

    @Test
    public void shouldEncodeBase64() throws Exception {
        String source = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String result = Utils.base64Encode(source);

        assertThat(result, is(notNullValue()));
        assertThat(result, is("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
    }

    @Test
    public void shouldPassHS256Verification() throws Exception {
        String jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        assertTrue(Utils.verifyHS(jwt.split("\\."), "secret", Algorithm.HS256));
    }

    @Test
    public void shouldFailHS256VerificationWithInvalidSecret() throws Exception {
        String jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        assertFalse(Utils.verifyHS(jwt.split("\\."), "not_real_secret", Algorithm.HS256));
    }

    @Test
    public void shouldThrowHS256VerificationWithNullSecret() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Secret cannot be null");
        String jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        Utils.verifyHS(jwt.split("\\."), null, Algorithm.HS256);
    }

    @Test
    public void shouldPassHS384Verification() throws Exception {
        String jwt = "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw";
        assertTrue(Utils.verifyHS(jwt.split("\\."), "secret", Algorithm.HS384));
    }

    @Test
    public void shouldFailHS384VerificationWithInvalidSecret() throws Exception {
        String jwt = "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw";
        assertFalse(Utils.verifyHS(jwt.split("\\."), "not_real_secret", Algorithm.HS384));
    }

    @Test
    public void shouldThrowHS384VerificationWithNullSecret() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Secret cannot be null");
        String jwt = "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw";
        Utils.verifyHS(jwt.split("\\."), null, Algorithm.HS384);
    }

    @Test
    public void shouldPassHS512Verification() throws Exception {
        String jwt = "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw";
        assertTrue(Utils.verifyHS(jwt.split("\\."), "secret", Algorithm.HS512));
    }

    @Test
    public void shouldFailHS512VerificationWithInvalidSecret() throws Exception {
        String jwt = "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw";
        assertFalse(Utils.verifyHS(jwt.split("\\."), "not_real_secret", Algorithm.HS512));
    }

    @Test
    public void shouldThrowHS512VerificationWithNullSecret() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Secret cannot be null");
        String jwt = "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw";
        Utils.verifyHS(jwt.split("\\."), null, Algorithm.HS512);
    }

    @Test
    public void shouldThrowWhenAlgorithmIsNotHS() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Algorithm must be one of HS256, HS384, or HS512.");
        String jwt = "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw";
        Utils.verifyHS(jwt.split("\\."), "secret", Algorithm.none);
    }

    @Test
    public void shouldThrowWhenAlgorithmIsNull() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Algorithm must be one of HS256, HS384, or HS512.");
        String jwt = "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw";
        Utils.verifyHS(jwt.split("\\."), "secret", null);
    }

}