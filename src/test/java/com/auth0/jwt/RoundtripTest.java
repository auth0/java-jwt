package com.auth0.jwt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

/**
 * Test things that are difficult using signer or verifier alone. In particular, setting
 * claims via Options produces output dependent on current time.
 *
 */
public class RoundtripTest {
    private static final String SECRET;
    private static final String SECRET_BASE64;
    static {
        try {
            SECRET = "my secret";
            SECRET_BASE64 = Base64.encodeBase64String(SECRET.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }
    private static JWTSigner signer = new JWTSigner(SECRET);
    private static JWTVerifier verifier = new JWTVerifier(SECRET_BASE64);
    
    /*
     * Roundtrip of different datatypes.
     */
    @Test
    public void shouldEmpty() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        String token = signer.sign(claims);
        Map<String, Object> decoded = verifier.verify(token);
        assertEquals(claims, decoded);
    }
    
    @Test
    public void shouldString() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("foo", "bar");
        String token = signer.sign(claims);
        Map<String, Object> decoded = verifier.verify(token);
        assertEquals(claims, decoded);
    }

    @Test
    public void shouldShort() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("foo", (short) -10);
        String token = signer.sign(claims);
        Map<String, Object> decoded = verifier.verify(token);
        Number fooValue = (Number) decoded.get("foo");
        decoded.put("foo", fooValue.shortValue());
        assertEquals(claims, decoded);
    }
    
    @Test
    public void shouldLong() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("foo", Long.MAX_VALUE);
        String token = signer.sign(claims);
        Map<String, Object> decoded = verifier.verify(token);
        assertEquals(claims, decoded);
    }
    
    @Test
    public void shouldObject() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        User user = new User();
        user.setUsername("foo");
        user.setPassword("bar");
        claims.put("user", user);
        String token = signer.sign(claims);
        Map<String, Object> decoded = verifier.verify(token);
        HashMap<String, String> expectedUser = new HashMap<String, String>();
        expectedUser.put("username", "foo");
        expectedUser.put("password", "bar");
        HashMap<String, Object> expected = new HashMap<String, Object>();
        expected.put("user", expectedUser);
        assertEquals(expected, decoded);
    }

    @Test
    public void shouldBoolean() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("foo", true);
        claims.put("bar", false);
        String token = signer.sign(claims);
        Map<String, Object> decoded = verifier.verify(token);
        assertEquals(claims, decoded);
    }

    /*
     * Setting claims via Options
     */
    
    @Test
    public void shouldOptionsIat() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        String token = signer.sign(claims,
                new JWTSigner.Options().setIssuedAt(true));
        Map<String, Object> decoded = verifier.verify(token);
        assertEquals(decoded.size(), 1);
        long iat = ((Number) decoded.get("iat")).longValue();
        assertTrue(iat >= System.currentTimeMillis() / 1000l);
        assertTrue(iat < System.currentTimeMillis() / 1000l + 10);
    }
    
    @Test
    public void shouldOptionsTimestamps() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        String token = signer.sign(claims,
                new JWTSigner.Options()
        .setExpirySeconds(50).setNotValidBeforeLeeway(10).setIssuedAt(true));
        Map<String, Object> decoded = verifier.verify(token);
        assertEquals(decoded.size(), 3);
        long iat = ((Number) decoded.get("iat")).longValue();
        long exp = ((Number) decoded.get("exp")).longValue();
        long nbf = ((Number) decoded.get("nbf")).longValue();
        assertEquals(exp, iat + 50);
        assertEquals(nbf, iat - 10);
    }
    
    @Test
    public void shouldOptionsJti() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        String token = signer.sign(claims,
                new JWTSigner.Options().setJwtId(true));
        Map<String, Object> decoded = verifier.verify(token);
        assertEquals(decoded.size(), 1);
        assertEquals(((String) decoded.get("jti")).length(), 36);
    }
}



