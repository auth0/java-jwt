package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.interfaces.JWT;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Date;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JWTVerifierTest {

    private static final long DATE_TOKEN_MS_VALUE = 1477592 * 1000;
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldThrowWhenInitializedWithoutAlgorithm() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Algorithm cannot be null");
        JWTVerifier.init(null);
    }

    @Test
    public void shouldThrowWhenAlgorithmDoesntMatchTheTokensAlgorithm() throws Exception {
        exception.expect(AlgorithmMismatchException.class);
        exception.expectMessage("The provided Algorithm doesn't match the one defined in the JWT's Header.");
        JWTVerifier verifier = JWTVerifier.init(Algorithm.HMAC512("secret")).build();
        verifier.verify("eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.s69x7Mmu4JqwmdxiK6sesALO7tcedbFsKEEITUxw9ho");
    }

    @Test
    public void shouldValidateIssuer() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        JWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withIssuer("auth0")
                .build()
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
                .build()
                .verify(token);
    }

    @Test
    public void shouldValidateSubject() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I";
        JWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withSubject("1234567890")
                .build()
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
                .build()
                .verify(token);
    }

    @Test
    public void shouldValidateAudience() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJNYXJrIn0.xWB6czYI0XObbVhLAxe55TwChWZg7zO08RxONWU2iY4";
        JWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAudience(new String[]{"Mark"})
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));

        String tokenArr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIl19.6WfbIt8m61f9WlCYIQn5CThvw4UNyC66qrPaoinfssw";
        JWT jwtArr = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAudience(new String[]{"Mark", "David"})
                .build()
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
                .build()
                .verify(token);
    }

    // Generic Delta
    @Test
    public void shouldAddDefaultTimeDeltaToDateClaims() throws Exception {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier verifier = JWTVerifier.init(algorithm)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, hasEntry("iat", (Object) 0L));
        assertThat(verifier.claims, hasEntry("exp", (Object) 0L));
        assertThat(verifier.claims, hasEntry("nbf", (Object) 0L));
    }

    @Test
    public void shouldAddCustomTimeDeltaToDateClaims() throws Exception {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier verifier = JWTVerifier.init(algorithm)
                .acceptTimeDelta(1234L)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, hasEntry("iat", (Object) 1234L));
        assertThat(verifier.claims, hasEntry("exp", (Object) 1234L));
        assertThat(verifier.claims, hasEntry("nbf", (Object) 1234L));
    }

    @Test
    public void shouldOverrideDefaultIssuedAtTimeDelta() throws Exception {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier verifier = JWTVerifier.init(algorithm)
                .acceptTimeDelta(1234L)
                .acceptIssuedAt(9999L)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, hasEntry("iat", (Object) 9999L));
        assertThat(verifier.claims, hasEntry("exp", (Object) 1234L));
        assertThat(verifier.claims, hasEntry("nbf", (Object) 1234L));
    }

    @Test
    public void shouldOverrideDefaultExpiresAtTimeDelta() throws Exception {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier verifier = JWTVerifier.init(algorithm)
                .acceptTimeDelta(1234L)
                .acceptExpiresAt(9999L)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, hasEntry("iat", (Object) 1234L));
        assertThat(verifier.claims, hasEntry("exp", (Object) 9999L));
        assertThat(verifier.claims, hasEntry("nbf", (Object) 1234L));
    }

    @Test
    public void shouldOverrideDefaultNotBeforeTimeDelta() throws Exception {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier verifier = JWTVerifier.init(algorithm)
                .acceptTimeDelta(1234L)
                .acceptNotBefore(9999L)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, hasEntry("iat", (Object) 1234L));
        assertThat(verifier.claims, hasEntry("exp", (Object) 1234L));
        assertThat(verifier.claims, hasEntry("nbf", (Object) 9999L));
    }

    @Test
    public void shouldThrowOnNegativeCustomTimeDelta() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Delta value can't be negative.");
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier.init(algorithm)
                .acceptTimeDelta(-1);
    }

    // Expires At
    @Test
    public void shouldValidateExpiresAtWithDelta() throws Exception {
        Clock clock = mock(Clock.class);
        when(clock.getToday()).thenReturn(new Date(DATE_TOKEN_MS_VALUE + 299));

        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc1OTJ9.isvT0Pqx0yjnZk53mUFSeYFJLDs-Ls9IsNAm86gIdZo";
        JWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .acceptExpiresAt(300)
                .build(clock)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateExpiresAtIfPresent() throws Exception {
        Clock clock = mock(Clock.class);
        when(clock.getToday()).thenReturn(new Date(DATE_TOKEN_MS_VALUE));

        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc1OTJ9.isvT0Pqx0yjnZk53mUFSeYFJLDs-Ls9IsNAm86gIdZo";
        JWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .build(clock)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidExpiresAtIfPresent() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage(startsWith("The Token has expired on"));
        Clock clock = mock(Clock.class);
        when(clock.getToday()).thenReturn(new Date(DATE_TOKEN_MS_VALUE + 10));

        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc1OTJ9.isvT0Pqx0yjnZk53mUFSeYFJLDs-Ls9IsNAm86gIdZo";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .build(clock)
                .verify(token);
    }

    @Test
    public void shouldThrowOnNegativeExpiresAtDelta() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Delta value can't be negative.");
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier.init(algorithm)
                .acceptExpiresAt(-1);
    }

    // Not before
    @Test
    public void shouldValidateNotBeforeWithDelta() throws Exception {
        Clock clock = mock(Clock.class);
        when(clock.getToday()).thenReturn(new Date(DATE_TOKEN_MS_VALUE - 299));

        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE0Nzc1OTJ9.wq4ZmnSF2VOxcQBxPLfeh1J2Ozy1Tj5iUaERm3FKaw8";
        JWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .acceptNotBefore(300)
                .build(clock)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidNotBeforeIfPresent() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage(startsWith("The Token can't be used before"));
        Clock clock = mock(Clock.class);
        when(clock.getToday()).thenReturn(new Date(DATE_TOKEN_MS_VALUE - 10));

        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE0Nzc1OTJ9.wq4ZmnSF2VOxcQBxPLfeh1J2Ozy1Tj5iUaERm3FKaw8";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .build(clock)
                .verify(token);
    }

    @Test
    public void shouldValidateNotBeforeIfPresent() throws Exception {
        Clock clock = mock(Clock.class);
        when(clock.getToday()).thenReturn(new Date(DATE_TOKEN_MS_VALUE));

        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc1OTJ9.isvT0Pqx0yjnZk53mUFSeYFJLDs-Ls9IsNAm86gIdZo";
        JWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .build(clock)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnNegativeNotBeforeDelta() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Delta value can't be negative.");
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier.init(algorithm)
                .acceptNotBefore(-1);
    }

    // Issued At
    @Test
    public void shouldValidateIssuedAtWithDelta() throws Exception {
        Clock clock = mock(Clock.class);
        when(clock.getToday()).thenReturn(new Date(DATE_TOKEN_MS_VALUE - 299));

        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0Nzc1OTJ9.0WJky9eLN7kuxLyZlmbcXRL3Wy8hLoNCEk5CCl2M4lo";
        JWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .acceptIssuedAt(300)
                .build(clock)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidIssuedAtIfPresent() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage(startsWith("The Token can't be used before"));
        Clock clock = mock(Clock.class);
        when(clock.getToday()).thenReturn(new Date(DATE_TOKEN_MS_VALUE - 10));

        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0Nzc1OTJ9.0WJky9eLN7kuxLyZlmbcXRL3Wy8hLoNCEk5CCl2M4lo";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .build(clock)
                .verify(token);
    }

    @Test
    public void shouldValidateIssuedAtIfPresent() throws Exception {
        Clock clock = mock(Clock.class);
        when(clock.getToday()).thenReturn(new Date(DATE_TOKEN_MS_VALUE));

        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0Nzc1OTJ9.0WJky9eLN7kuxLyZlmbcXRL3Wy8hLoNCEk5CCl2M4lo";
        JWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .build(clock)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnNegativeIssuedAtDelta() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Delta value can't be negative.");
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier.init(algorithm)
                .acceptIssuedAt(-1);
    }

    @Test
    public void shouldValidateJWTId() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqd3RfaWRfMTIzIn0.0kegfXUvwOYioP8PDaLMY1IlV8HOAzSVz3EGL7-jWF4";
        JWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withJWTId("jwt_id_123")
                .build()
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
                .build()
                .verify(token);
    }

    @Test
    public void shouldRemoveClaimWhenPassingNull() throws Exception {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier verifier = JWTVerifier.init(algorithm)
                .withIssuer("iss")
                .withIssuer(null)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, not(hasKey("iss")));
    }

    @Test
    public void shouldSkipClaimValidationsIfNoClaimsRequired() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M";
        JWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }
}
