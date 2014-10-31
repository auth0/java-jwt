package com.auth0.jwt;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import org.junit.Test;

public class JWTSignerTest {
    private static JWTSigner signer = new JWTSigner("my secret");
    
    @Test
    public void shouldSignEmpty() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        String token = signer.sign(claims);
        assertEquals("eyJ0eXBlIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.e30.22wExCVEVtV1rZU51TB9W64deZc_ZN7mc_Z1Yq0dmo0", token);
    }

    @Test
    public void shouldSignEmptyTwoParams() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        String token = signer.sign(claims);
        assertEquals("eyJ0eXBlIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.e30.22wExCVEVtV1rZU51TB9W64deZc_ZN7mc_Z1Yq0dmo0", token);
    }
    
    @Test
    public void shouldSignStringOrURI1() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("iss", "foo");
        String token = signer.sign(claims);
        assertEquals("eyJ0eXBlIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJpc3MiOiJmb28ifQ.7VNaEEPhOiEXfEgPrxkFFhQCAxl9X3F20sq9KVaVtJM", token);
    }
    
    @Test
    public void shouldSignStringOrURI2() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("sub", "http://foo");
        String token = signer.sign(claims);
        assertEquals("eyJ0eXBlIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJodHRwOi8vZm9vIn0.GYhCLgXYbAXp2Lr8T2yif7ylBVK1XZFkO8hEBa8WP8U", token);
    }
    
    @Test
    public void shouldSignStringOrURI3() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("aud", "");
        String token = signer.sign(claims);
        assertEquals("eyJ0eXBlIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJhdWQiOiIifQ.qobL4k5su7O7ssfCr7drTScIhWjheIc9uxipkR9MC0A", token);
    }
    
    @Test
    public void shouldSignStringOrURICollection() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        LinkedList<String> aud = new LinkedList<String>();
        aud.add("xyz");
        aud.add("ftp://foo");
        claims.put("aud", aud);
        String token = signer.sign(claims);
        assertEquals("eyJ0eXBlIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJhdWQiOlsieHl6IiwiZnRwOi8vZm9vIl19.xL_8PVO_8isoFSud1Nlqi8rA3jvdD5zALN3tjcQ0vbk", token);
    }
    
    @Test
    public void shouldSignIntDate1() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("exp", 123);
        String token = signer.sign(claims);
        assertEquals("eyJ0eXBlIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJleHAiOjEyM30.1pI_TNQDCsKc3IEVX_2fcAKJmJZ8j3hhOfAvAdqKE0s", token);
    }

    @Test
    public void shouldSignIntDate2() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("nbf", 0);
        String token = signer.sign(claims);
        assertEquals("eyJ0eXBlIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJuYmYiOjB9.uxwAmWxxPZwGRgfiXOHGxrXmxgay6tv93Pyiya3O5dE", token);
    }
    
    @Test
    public void shouldSignIntDate3() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("iat", Long.MAX_VALUE);
        String token = signer.sign(claims);
        assertEquals("eyJ0eXBlIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJpYXQiOjkyMjMzNzIwMzY4NTQ3NzU4MDd9.nsfMBVmmDR0u1tVN54UzHDZL2wylDA50YjzN2WxZEsU", token);
    }
    
    @Test
    public void shouldSignString() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("jti", "foo");
        String token = signer.sign(claims);
        assertEquals("eyJ0eXBlIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJqdGkiOiJmb28ifQ.6X8nx7sLNxdc4mYNL__gd0ab-m8QfheVHT2Y_2DQJMU", token);
    }
    
    @Test
    public void shouldSignNullEqualsMissing() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        for (String claimName : Arrays.asList("iss", "sub", "aud", "exp", "nbf", "iat", "jti")) {
            claims.put(claimName, null);
        }
        String token = signer.sign(claims);
        assertEquals("eyJ0eXBlIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.e30.22wExCVEVtV1rZU51TB9W64deZc_ZN7mc_Z1Yq0dmo0", token);
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
        assertEquals("eyJ0eXBlIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.e30.22wExCVEVtV1rZU51TB9W64deZc_ZN7mc_Z1Yq0dmo0", token);
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
        assertEquals("eyJ0eXBlIjoiSldUIiwiYWxnIjoiSFM1MTIifQ.e30.gH4cjvHOMA2QcZjwSqO-VZ4tyah8hDMVqUGAOth7vBWweOIzCwohpOlpLoRCKeDD3PyMqE1gwHqGuWDk2VuYmQ", token);
    }

}
