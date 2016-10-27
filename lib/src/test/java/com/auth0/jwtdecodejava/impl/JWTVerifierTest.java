package com.auth0.jwtdecodejava.impl;

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
    public void shouldValidateIssuer() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.MT8JrEvIB69bH5W9RUR2ap-H3e69fM7LEQCiZF-7FbI";
        JWT jwt = JWTVerifier.init()
                .withIssuer("auth0")
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidIssuer() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'iss' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.MT8JrEvIB69bH5W9RUR2ap-H3e69fM7LEQCiZF-7FbI";
        JWTVerifier.init()
                .withIssuer("invalid")
                .verify(token);
    }


    @Test
    public void shouldValidateSubject() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I";
        JWT jwt = JWTVerifier.init()
                .withSubject("1234567890")
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidSubject() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'sub' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I";
        JWTVerifier.init()
                .withSubject("invalid")
                .verify(token);
    }

    @Test
    public void shouldValidateAudience() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJNYXJrIn0.MT8JrEvIB69bH5W9RUR2ap-H3e69fM7LEQCiZF-7FbI";
        JWT jwt = JWTVerifier.init()
                .withAudience(new String[]{"Mark"})
                .verify(token);

        assertThat(jwt, is(notNullValue()));

        String tokenArr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIl19.MT8JrEvIB69bH5W9RUR2ap-H3e69fM7LEQCiZF-7FbI";
        JWT jwtArr = JWTVerifier.init()
                .withAudience(new String[]{"Mark", "David"})
                .verify(tokenArr);

        assertThat(jwtArr, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidAudience() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'aud' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I";
        JWTVerifier.init()
                .withAudience(new String[]{"nope"})
                .verify(token);
    }

    @Test
    public void shouldValidateExpiresAt() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc1OTJ9.MT8JrEvIB69bH5W9RUR2ap-H3e69fM7LEQCiZF-7FbI";
        JWT jwt = JWTVerifier.init()
                .withExpiresAt(new Date(1477592000))
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidExpiresAt() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'exp' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc1OTJ9.MT8JrEvIB69bH5W9RUR2ap-H3e69fM7LEQCiZF-7FbI";
        JWTVerifier.init()
                .withExpiresAt(new Date())
                .verify(token);
    }

    @Test
    public void shouldValidateNotBefore() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE0Nzc1OTJ9.MT8JrEvIB69bH5W9RUR2ap-H3e69fM7LEQCiZF-7FbI";
        JWT jwt = JWTVerifier.init()
                .withNotBefore(new Date(1477592000))
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidNotBefore() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'nbf' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE0Nzc1OTJ9.MT8JrEvIB69bH5W9RUR2ap-H3e69fM7LEQCiZF-7FbI";
        JWTVerifier.init()
                .withNotBefore(new Date())
                .verify(token);
    }

    @Test
    public void shouldValidateIssuedAt() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0Nzc1OTJ9.MT8JrEvIB69bH5W9RUR2ap-H3e69fM7LEQCiZF-7FbI";
        JWT jwt = JWTVerifier.init()
                .withIssuedAt(new Date(1477592000))
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidIssuedAt() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'iat' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0Nzc1OTJ9.MT8JrEvIB69bH5W9RUR2ap-H3e69fM7LEQCiZF-7FbI";
        JWTVerifier.init()
                .withIssuedAt(new Date())
                .verify(token);
    }

    @Test
    public void shouldValidateJWTId() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqd3RfaWRfMTIzIn0.MT8JrEvIB69bH5W9RUR2ap-H3e69fM7LEQCiZF-7FbI";
        JWT jwt = JWTVerifier.init()
                .withJWTId("jwt_id_123")
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidJWTId() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'jti' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqd3RfaWRfMTIzIn0.MT8JrEvIB69bH5W9RUR2ap-H3e69fM7LEQCiZF-7FbI";
        JWTVerifier.init()
                .withJWTId("invalid")
                .verify(token);
    }

    @Test
    public void shouldSkipClaimValidationsIfNoClaimsRequired() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.MT8JrEvIB69bH5W9RUR2ap-H3e69fM7LEQCiZF-7FbI";
        JWT jwt = JWTVerifier.init()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }
}
