package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;

public class JWTCreatorTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldThrowWhenInitializedWithoutAlgorithm() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Algorithm cannot be null");
        JWTCreator.init(null);
    }

    @SuppressWarnings("Convert2Diamond")
    @Test
    public void shouldAddHeader() throws Exception {
        Map<String, Object> header = new HashMap<String, Object>();
        header.put("asd", 123);
        String signed = JWTCreator.init(Algorithm.HMAC256("secret"))
                .withHeader(header)
                .sign();

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[0], is("eyJhbGciOiJIUzI1NiIsImFzZCI6MTIzfQ"));
    }

    @Test
    public void shouldAddIssuer() throws Exception {
        String signed = JWTCreator.init(Algorithm.HMAC256("secret"))
                .withIssuer("auth0")
                .sign();

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[1], is("eyJpc3MiOiJhdXRoMCJ9"));
    }

    @Test
    public void shouldAddSubject() throws Exception {
        String signed = JWTCreator.init(Algorithm.HMAC256("secret"))
                .withSubject("1234567890")
                .sign();

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[1], is("eyJzdWIiOiIxMjM0NTY3ODkwIn0"));
    }

    @Test
    public void shouldAddAudience() throws Exception {
        String signed = JWTCreator.init(Algorithm.HMAC256("secret"))
                .withAudience(new String[]{"Mark"})
                .sign();

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[1], is("eyJhdWQiOiJNYXJrIn0"));


        String signedArr = JWTCreator.init(Algorithm.HMAC256("secret"))
                .withAudience(new String[]{"Mark", "David"})
                .sign();

        assertThat(signedArr, is(notNullValue()));
        assertThat(SignUtils.splitToken(signedArr)[1], is("eyJhdWQiOlsiTWFyayIsIkRhdmlkIl19"));
    }

    @Test
    public void shouldAddExpiresAt() throws Exception {
        String signed = JWTCreator.init(Algorithm.HMAC256("secret"))
                .withExpiresAt(new Date(1477592000))
                .sign();

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[1], is("eyJleHAiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddNotBefore() throws Exception {
        String signed = JWTCreator.init(Algorithm.HMAC256("secret"))
                .withNotBefore(new Date(1477592000))
                .sign();

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[1], is("eyJuYmYiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddIssuedAt() throws Exception {
        String signed = JWTCreator.init(Algorithm.HMAC256("secret"))
                .withIssuedAt(new Date(1477592000))
                .sign();

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[1], is("eyJpYXQiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddJWTId() throws Exception {
        String signed = JWTCreator.init(Algorithm.HMAC256("secret"))
                .withJWTId("jwt_id_123")
                .sign();

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[1], is("eyJqdGkiOiJqd3RfaWRfMTIzIn0"));
    }


    @Test
    public void shouldRemoveClaimWhenPassingNull() throws Exception {
        String signed = JWTCreator.init(Algorithm.HMAC256("secret"))
                .withIssuer("iss")
                .withIssuer(null)
                .sign();

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[1], is("e30"));
    }

    @Test
    public void shouldSetCorrectAlgorithmInTheHeader() throws Exception {
        String signed = JWTCreator.init(Algorithm.HMAC256("secret"))
                .sign();

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[0], is("eyJhbGciOiJIUzI1NiJ9"));
    }

    @Test
    public void shouldSetEmptySignatureIfAlgorithmIsNone() throws Exception {
        String signed = JWTCreator.init(Algorithm.none())
                .sign();
        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[2], is(""));
    }

}