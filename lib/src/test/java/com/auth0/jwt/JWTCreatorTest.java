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
    public void shouldThrowWhenRequestingSignWithoutAlgorithm() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Algorithm cannot be null");
        JWTCreator.init()
                .sign(null);
    }

    @SuppressWarnings("Convert2Diamond")
    @Test
    public void shouldAddHeader() throws Exception {
        Map<String, Object> header = new HashMap<String, Object>();
        header.put("asd", 123);
        String signed = JWTCreator.init()
                .withHeader(header)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[0], is("eyJhbGciOiJIUzI1NiIsImFzZCI6MTIzfQ"));
    }

    @Test
    public void shouldAddIssuer() throws Exception {
        String signed = JWTCreator.init()
                .withIssuer("auth0")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[1], is("eyJpc3MiOiJhdXRoMCJ9"));
    }

    @Test
    public void shouldAddSubject() throws Exception {
        String signed = JWTCreator.init()
                .withSubject("1234567890")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[1], is("eyJzdWIiOiIxMjM0NTY3ODkwIn0"));
    }

    @Test
    public void shouldAddAudience() throws Exception {
        String signed = JWTCreator.init()
                .withAudience(new String[]{"Mark"})
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[1], is("eyJhdWQiOiJNYXJrIn0"));


        String signedArr = JWTCreator.init()
                .withAudience(new String[]{"Mark", "David"})
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signedArr, is(notNullValue()));
        assertThat(SignUtils.splitToken(signedArr)[1], is("eyJhdWQiOlsiTWFyayIsIkRhdmlkIl19"));
    }

    @Test
    public void shouldAddExpiresAt() throws Exception {
        String signed = JWTCreator.init()
                .withExpiresAt(new Date(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[1], is("eyJleHAiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddNotBefore() throws Exception {
        String signed = JWTCreator.init()
                .withNotBefore(new Date(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[1], is("eyJuYmYiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddIssuedAt() throws Exception {
        String signed = JWTCreator.init()
                .withIssuedAt(new Date(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[1], is("eyJpYXQiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddJWTId() throws Exception {
        String signed = JWTCreator.init()
                .withJWTId("jwt_id_123")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[1], is("eyJqdGkiOiJqd3RfaWRfMTIzIn0"));
    }


    @Test
    public void shouldRemoveClaimWhenPassingNull() throws Exception {
        String signed = JWTCreator.init()
                .withIssuer("iss")
                .withIssuer(null)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[1], is("e30"));
    }

    @Test
    public void shouldSetCorrectAlgorithmInTheHeader() throws Exception {
        String signed = JWTCreator.init()
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[0], is("eyJhbGciOiJIUzI1NiJ9"));
    }

    @Test
    public void shouldSetEmptySignatureIfAlgorithmIsNone() throws Exception {
        String signed = JWTCreator.init()
                .sign(Algorithm.none());
        assertThat(signed, is(notNullValue()));
        assertThat(SignUtils.splitToken(signed)[2], is(""));
    }

}