package com.auth0.jwt;

import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class JWTSignerTest {

    private final String header = "{\"alg\":\"HS256\"}";
    private final String payload = "{\"iat\":1477592}";
    private JWTSigner signer;

    @Before
    public void setUp() throws Exception {
        signer = new JWTSigner();
    }

    @Test
    public void shouldSign() throws Exception {
        String originalJwt = "eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0Nzc1OTJ9.5o1CKlLFjKKcddZzoarQ37pq7qZqNPav3sdZ_bsZaD4";
        String result = signer.sign(header, payload);

        assertThat(result, is(originalJwt));
    }

}