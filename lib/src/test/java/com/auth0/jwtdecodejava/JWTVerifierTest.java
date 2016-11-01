package com.auth0.jwtdecodejava;

import com.auth0.jwtdecodejava.algorithms.Algorithm;
import com.auth0.jwtdecodejava.exceptions.InvalidClaimException;
import com.auth0.jwtdecodejava.interfaces.JWT;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Date;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;

public class JWTVerifierTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldThrowWhenInitializedWithoutAlgorithm() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Algorithm cannot be null");
        JWTVerifier.init(null);
    }

    @Test
    public void shouldValidateIssuer() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        JWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withIssuer("auth0")
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidIssuer() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'iss' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withIssuer("invalid")
                .verify(token);
    }

    @Test
    public void shouldValidateSubject() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I";
        JWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withSubject("1234567890")
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidSubject() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'sub' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withSubject("invalid")
                .verify(token);
    }

    @Test
    public void shouldValidateAudience() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJNYXJrIn0.xWB6czYI0XObbVhLAxe55TwChWZg7zO08RxONWU2iY4";
        JWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAudience(new String[]{"Mark"})
                .verify(token);

        assertThat(jwt, is(notNullValue()));

        String tokenArr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIl19.6WfbIt8m61f9WlCYIQn5CThvw4UNyC66qrPaoinfssw";
        JWT jwtArr = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAudience(new String[]{"Mark", "David"})
                .verify(tokenArr);

        assertThat(jwtArr, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidAudience() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'aud' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAudience(new String[]{"nope"})
                .verify(token);
    }

    @Test
    public void shouldValidateExpiresAt() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc1OTJ9.isvT0Pqx0yjnZk53mUFSeYFJLDs-Ls9IsNAm86gIdZo";
        JWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withExpiresAt(new Date(1477592000))
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidExpiresAt() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'exp' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc1OTJ9.isvT0Pqx0yjnZk53mUFSeYFJLDs-Ls9IsNAm86gIdZo";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withExpiresAt(new Date())
                .verify(token);
    }

    @Test
    public void shouldValidateNotBefore() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE0Nzc1OTJ9.wq4ZmnSF2VOxcQBxPLfeh1J2Ozy1Tj5iUaERm3FKaw8";
        JWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withNotBefore(new Date(1477592000))
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidNotBefore() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'nbf' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE0Nzc1OTJ9.wq4ZmnSF2VOxcQBxPLfeh1J2Ozy1Tj5iUaERm3FKaw8";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withNotBefore(new Date())
                .verify(token);
    }

    @Test
    public void shouldValidateIssuedAt() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0Nzc1OTJ9.0WJky9eLN7kuxLyZlmbcXRL3Wy8hLoNCEk5CCl2M4lo";
        JWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withIssuedAt(new Date(1477592000))
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidIssuedAt() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'iat' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0Nzc1OTJ9.0WJky9eLN7kuxLyZlmbcXRL3Wy8hLoNCEk5CCl2M4lo";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withIssuedAt(new Date())
                .verify(token);
    }

    @Test
    public void shouldValidateJWTId() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqd3RfaWRfMTIzIn0.0kegfXUvwOYioP8PDaLMY1IlV8HOAzSVz3EGL7-jWF4";
        JWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withJWTId("jwt_id_123")
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidJWTId() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'jti' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqd3RfaWRfMTIzIn0.0kegfXUvwOYioP8PDaLMY1IlV8HOAzSVz3EGL7-jWF4";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withJWTId("invalid")
                .verify(token);
    }

    @Test
    public void shouldSkipClaimValidationsIfNoClaimsRequired() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M";
        JWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }
}
