package com.auth0.jwt;

import com.auth0.jwt.Algorithm;
import com.auth0.jwt.JWTSigner;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;

import static org.junit.Assert.assertEquals;

/**
 * General library JwtSigner unit tests using byte constructor alternative for secret
 */
public class JWTSignerBytesTest {
    private static JWTSigner signer = new JWTSigner(new byte[] { 109, 121, 32, 115, 101, 99, 114, 101, 116});
    
    @Test
    public void shouldSignEmpty() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        String token = signer.sign(claims);
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.86pkOAQxvnSDd91EThNNpOTbO-hbvxdssnFjQqT04NU", token);
    }

    @Test
    public void shouldSignEmptyTwoParams() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        String token = signer.sign(claims);
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.86pkOAQxvnSDd91EThNNpOTbO-hbvxdssnFjQqT04NU", token);
    }

    @Test
    public void shouldSignStringOrURI1() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("iss", "foo");
        String token = signer.sign(claims);
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJmb28ifQ.UbvkKJx4ubG9SQYs3Hpe6FJl1ix89jSLw0I9GNTnLgY", token);
    }

    @Test
    public void shouldSignStringOrURI2() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("sub", "http://foo");
        String token = signer.sign(claims);
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJodHRwOi8vZm9vIn0.EaYoTXJWUNd_1tWfZo4EZoKUP8hVMJm1LHBQNo4Xfwg", token);
    }
    
    @Test
    public void shouldSignStringOrURI3() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("aud", "");
        String token = signer.sign(claims);
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiIifQ.T2EKheH_WVVwybctic8Sqk89miYVKADW0AeXOicDbz8", token);
    }
    
    @Test
    public void shouldSignStringOrURICollection() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        LinkedList<String> aud = new LinkedList<String>();
        aud.add("xyz");
        aud.add("ftp://foo");
        claims.put("aud", aud);
        String token = signer.sign(claims);
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsieHl6IiwiZnRwOi8vZm9vIl19.WGpsdOnLJ2k7Rr4WeEuabHO4wNQIhJfPMZot1DrTUgA", token);
    }
    
    @Test
    public void shouldSignIntDate1() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("exp", 123);
        String token = signer.sign(claims);
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjEyM30.FzAXEHf0LVQPOyRQFftA1VBAj8RmZGEfwQIPSfg_DUg", token);
    }

    @Test
    public void bytes_shouldSignIntDate1() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("exp", 123);
        String token = signer.sign(claims);
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjEyM30.FzAXEHf0LVQPOyRQFftA1VBAj8RmZGEfwQIPSfg_DUg", token);
    }

    @Test
    public void shouldSignIntDate2() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("nbf", 0);
        String token = signer.sign(claims);
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYmYiOjB9.ChHEHjtyr4qOUMu6KDsa2BjGXtkGurboD5ljr99gVzw", token);
    }

    @Test
    public void shouldSignIntDate3() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("iat", Long.MAX_VALUE);
        String token = signer.sign(claims);
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjkyMjMzNzIwMzY4NTQ3NzU4MDd9.7yrsheXoAuqk5hDcbKmT3l6aDNNr7RMnbVe6kVkvv4M", token);
    }

    @Test
    public void bytes_shouldSignIntDate2() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("nbf", 0);
        String token = signer.sign(claims);
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYmYiOjB9.ChHEHjtyr4qOUMu6KDsa2BjGXtkGurboD5ljr99gVzw", token);
    }
    
    @Test
    public void shouldSignString() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("jti", "foo");
        String token = signer.sign(claims);
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJmb28ifQ.CriA-W8LKO4bCxy3e2Nu7kx2MxgcHGyFu_GVLMX3bko", token);
    }
    
    @Test
    public void shouldSignNullEqualsMissing() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        for (String claimName : Arrays.asList("iss", "sub", "aud", "exp", "nbf", "iat", "jti")) {
            claims.put(claimName, null);
        }
        String token = signer.sign(claims);
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.86pkOAQxvnSDd91EThNNpOTbO-hbvxdssnFjQqT04NU", token);
    }
    
    @Test(expected = Exception.class)
    public void shouldFailExpectStringOrURI1() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("iss", 0);
        signer.sign(claims);
    }
    
    @Test(expected = Exception.class)
    public void shouldFailExpectStringOrURI2() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("sub", ":");
        signer.sign(claims);
    }
    
    @Test(expected = Exception.class)
    public void shouldFailExpectStringOrURICollection1() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("aud", 0);
        signer.sign(claims);
    }
    
    @Test(expected = Exception.class)
    public void shouldFailExpectStringOrURICollection2() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("aud", Arrays.asList(0));
        signer.sign(claims);
    }
    
    @Test(expected = Exception.class)
    public void shouldFailExpectStringOrURICollection3() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("aud", Arrays.asList(":"));
        signer.sign(claims);
    }
    
    @Test(expected = Exception.class)
    public void shouldFailExpectIntDate1() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("exp", -1);
        signer.sign(claims);
    }
    
    @Test(expected = Exception.class)
    public void shouldFailExpectIntDate2() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("nbf", "100");
        signer.sign(claims);
    }
    
    @Test(expected = Exception.class)
    public void shouldFailExpectString() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("jti", 100);
        signer.sign(claims);
    }
    
    @Test
    public void shouldOptionsNone() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        String token = signer.sign(claims, new JWTSigner.Options());
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.86pkOAQxvnSDd91EThNNpOTbO-hbvxdssnFjQqT04NU", token);
    }
    
    @Test
    public void shouldOptionsAll() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        signer.sign(claims, new JWTSigner.Options()
                .setExpirySeconds(1000).setNotValidBeforeLeeway(5)
                .setIssuedAt(true).setJwtId(true));
    }

    @Test
    public void shouldOptionsAlgorithm() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        String token = signer.sign(claims,
                new JWTSigner.Options().setAlgorithm(Algorithm.HS512));
        assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.e30.11MgCe-_uiheyy_kARCwhSZbeq3IkMn40GLQkczQ4Bjn_lkCYfSeqz0HeeYpitksiQ2bW47N0oGKCOYOlmQPyg", token);
    }

}
