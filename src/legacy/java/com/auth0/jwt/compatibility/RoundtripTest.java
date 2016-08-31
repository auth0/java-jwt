package com.auth0.jwt.compatibility;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

/**
 * Test things that are difficult using signer or verifier alone. In particular, setting
 * claims via Options produces output dependent on current time.
 *
 */
public class RoundtripTest {
    private static final String SECRET;
    static {
        SECRET = "my secret";
    }
    private static com.auth0.jwt.JWTSigner signer = new com.auth0.jwt.JWTSigner(SECRET);
    private static com.auth0.jwt.JWTVerifier verifier = new com.auth0.jwt.JWTVerifier(SECRET);
    
	private static com.auth0.jwt.old.JWTSigner signerLegacy = new com.auth0.jwt.old.JWTSigner(new byte[] { 109, 121, 32, 115, 101, 99, 114, 101, 116});
    private static com.auth0.jwt.old.JWTVerifier verifierLegacy = new com.auth0.jwt.old.JWTVerifier(SECRET);

    /*
     * Roundtrip of different datatypes.
     */
    @Test
    public void shouldEmptyCross1() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        String token = signerLegacy.sign(claims);
        Map<String, Object> decoded = verifier.verify(token);
        assertEquals(claims, decoded);
    }
    
    @Test
    public void shouldEmptyCross2() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        String token = signer.sign(claims);
        Map<String, Object> decoded = verifierLegacy.verify(token);
        assertEquals(claims, decoded);
    }
    
	@Test
    public void shouldStringCross1() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("foo", "bar");
        String token = signerLegacy.sign(claims);
        Map<String, Object> decoded = verifier.verify(token);
        assertEquals(claims, decoded);
    }

	@Test
    public void shouldStringCross2() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("foo", "bar");
        String token = signer.sign(claims);
        Map<String, Object> decoded = verifierLegacy.verify(token);
        assertEquals(claims, decoded);
    }

    @Test
    public void shouldShortCross1() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("foo", (short) -10);
        String token = signerLegacy.sign(claims);
        Map<String, Object> decoded = verifier.verify(token);
        Number fooValue = (Number) decoded.get("foo");
        decoded.put("foo", fooValue.shortValue());
        assertEquals(claims, decoded);
    }
    
    @Test
    public void shouldShortCross2() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("foo", (short) -10);
        String token = signer.sign(claims);
        Map<String, Object> decoded = verifierLegacy.verify(token);
        Number fooValue = (Number) decoded.get("foo");
        decoded.put("foo", fooValue.shortValue());
        assertEquals(claims, decoded);
    }
    
    @Test
    public void shouldLongCross1() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("foo", Long.MAX_VALUE);
        String token = signerLegacy.sign(claims);
        Map<String, Object> decoded = verifier.verify(token);
        assertEquals(claims, decoded);
    }
    
    @Test
    public void shouldLongCross2() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("foo", Long.MAX_VALUE);
        String token = signer.sign(claims);
        Map<String, Object> decoded = verifierLegacy.verify(token);
        assertEquals(claims, decoded);
    }
    
    @Test
    public void shouldObjectCross1() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        User user = new User();
        user.setUsername("foo");
        user.setPassword("bar");
        claims.put("user", user);
        String token = signerLegacy.sign(claims);
        Map<String, Object> decoded = verifier.verify(token);
        HashMap<String, String> expectedUser = new HashMap<String, String>();
        expectedUser.put("username", "foo");
        expectedUser.put("password", "bar");
        HashMap<String, Object> expected = new HashMap<String, Object>();
        expected.put("user", expectedUser);
        assertEquals(expected, decoded);
    }

    @Test
    public void shouldObjectCross2() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        User user = new User();
        user.setUsername("foo");
        user.setPassword("bar");
        claims.put("user", user);
        String token = signer.sign(claims);
        Map<String, Object> decoded = verifierLegacy.verify(token);
        HashMap<String, String> expectedUser = new HashMap<String, String>();
        expectedUser.put("username", "foo");
        expectedUser.put("password", "bar");
        HashMap<String, Object> expected = new HashMap<String, Object>();
        expected.put("user", expectedUser);
        assertEquals(expected, decoded);
    }

    @Test
    public void shouldBooleanCross1() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("foo", true);
        claims.put("bar", false);
        String token = signerLegacy.sign(claims);
        Map<String, Object> decoded = verifier.verify(token);
        assertEquals(claims, decoded);
    }

    @Test
    public void shouldBooleanCross2() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("foo", true);
        claims.put("bar", false);
        String token = signer.sign(claims);
        Map<String, Object> decoded = verifierLegacy.verify(token);
        assertEquals(claims, decoded);
    }

    /*
     * Setting claims via Options
     */
    @Test
    public void shouldOptionsIatCross1() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        long before = System.currentTimeMillis();
        String token = signerLegacy.sign(claims, new com.auth0.jwt.old.JWTSigner.Options().setIssuedAt(true));
        long after = System.currentTimeMillis();
        Map<String, Object> decoded = verifier.verify(token);

        assertEquals(decoded.size(), 1);
        long iat = ((Number) decoded.get("iat")).longValue();
        assertTrue(iat >= before / 1000l);
        assertTrue(iat <= after / 1000l);
    }

    @Test
    public void shouldOptionsIatCross2() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        long before = System.currentTimeMillis();
        String token = signer.sign(claims, new com.auth0.jwt.JWTSigner.Options().setIssuedAt(true));
        long after = System.currentTimeMillis();
        Map<String, Object> decoded = verifierLegacy.verify(token);

        assertEquals(decoded.size(), 1);
        long iat = ((Number) decoded.get("iat")).longValue();
        assertTrue(iat >= before / 1000l);
        assertTrue(iat <= after / 1000l);
    }

    @Test
    public void shouldOptionsTimestampsCross1() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        String token = signerLegacy.sign(claims,
                new com.auth0.jwt.old.JWTSigner.Options()
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
    public void shouldOptionsTimestampsCross2() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        String token = signer.sign(claims,
                new com.auth0.jwt.JWTSigner.Options()
        .setExpirySeconds(50).setNotValidBeforeLeeway(10).setIssuedAt(true));
        Map<String, Object> decoded = verifierLegacy.verify(token);
        assertEquals(decoded.size(), 3);
        long iat = ((Number) decoded.get("iat")).longValue();
        long exp = ((Number) decoded.get("exp")).longValue();
        long nbf = ((Number) decoded.get("nbf")).longValue();
        assertEquals(exp, iat + 50);
        assertEquals(nbf, iat - 10);
    }
    
    @Test
    public void shouldOptionsJtiCross1() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        String token = signerLegacy.sign(claims,
                new com.auth0.jwt.old.JWTSigner.Options().setJwtId(true));
        Map<String, Object> decoded = verifier.verify(token);
        assertEquals(decoded.size(), 1);
        assertEquals(((String) decoded.get("jti")).length(), 36);
    }

	@Test
    public void shouldOptionsJtiCross2() throws Exception {
        HashMap<String, Object> claims = new HashMap<String, Object>();
        String token = signer.sign(claims,
                new com.auth0.jwt.JWTSigner.Options().setJwtId(true));
        Map<String, Object> decoded = verifierLegacy.verify(token);
        assertEquals(decoded.size(), 1);
        assertEquals(((String) decoded.get("jti")).length(), 36);
    }
}



