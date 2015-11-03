package com.auth0.jwt;


import org.junit.Test;

import java.security.SignatureException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.boon.Lists;

import static org.junit.Assert.assertEquals;

public class JWTVerifierTest {
	
    
	@Test(expected = IllegalArgumentException.class)
    public void constructorShouldFailOnEmptySecret() {
        new JWTVerifier("");
    }

    @Test(expected = IllegalStateException.class)
    public void shouldFailOn1Segments() throws Exception {
        new JWTVerifier("such secret").verify("crypto");
    }

    @Test(expected = IllegalStateException.class)
    public void shouldFailOn2Segments() throws Exception {
        new JWTVerifier("such secret").verify("much.crypto");
    }

    @Test(expected = IllegalStateException.class)
    public void shouldFailOn4Segments() throws Exception {
        new JWTVerifier("such secret").verify("much.crypto.so.token");
    }

    @Test(expected = IllegalStateException.class)
    public void shouldFailOnEmptyStringToken() throws Exception {
        new JWTVerifier("such secret").verify("");
    }

    @Test(expected = IllegalStateException.class)
    public void shouldFailOnNullToken() throws Exception {
        new JWTVerifier("such secret").verify(null);
    }

    @Test(expected = IllegalStateException.class)
    public void shouldFailIfAlgorithmIsNotSetOnToken() throws Exception {
        new JWTVerifier("such secret").getAlgorithm(new HashMap<>());
    }

    @Test(expected = IllegalStateException.class)
    public void shouldFailIfAlgorithmIsNotSupported() throws Exception {
        new JWTVerifier("such secret").getAlgorithm(createSingletonJSONNode("alg", "doge-crypt"));
    }

    @Test
    public void shouldWorkIfAlgorithmIsSupported() throws Exception {
       new JWTVerifier("such secret").getAlgorithm(createSingletonJSONNode("alg", "HS256"));
    }

    @Test(expected = SignatureException.class)
    public void shouldFailOnInvalidSignature() throws Exception {
        final String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                "." +
                "suchsignature_plzvalidate_zomgtokens";
        String secret = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
        new JWTVerifier(secret, "audience").verifySignature(jws.split("\\."), "HmacSHA256");
    }

    @Test
    public void shouldVerifySignature() throws Exception {
        final String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                "." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
		
        byte[] secret = Base64.getUrlDecoder().decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");
        new JWTVerifier(secret, "audience")
                .verifySignature(jws.split("\\."), "HmacSHA256");
    }

    @Test(expected = JWTExpiredException.class)
    public void shouldFailWhenExpired1SecondAgoLong() throws Exception {
        new JWTVerifier("such secret").verifyExpiration(
                createSingletonJSONNode("exp", System.currentTimeMillis() / 1000L - 1L));
    }

    @Test(expected = JWTExpiredException.class)
    public void shouldFailWhenExpired1SecondAgoString() throws Exception {
        new JWTVerifier("such secret").verifyExpiration(
                createSingletonJSONNode("exp", Long.toString(System.currentTimeMillis() / 1000L - 1L)));
    }

    @Test
    public void shouldVerifyExpirationLong() throws Exception {
        new JWTVerifier("such secret").verifyExpiration(
                createSingletonJSONNode("exp", System.currentTimeMillis() / 1000L + 50L));
    }

    @Test
    public void shouldVerifyExpirationString() throws Exception {
        new JWTVerifier("such secret").verifyExpiration(
                createSingletonJSONNode("exp", Long.toString(System.currentTimeMillis() / 1000L + 50L)));
    }

    @Test
    public void shouldVerifyIssuer() throws Exception {
        new JWTVerifier("such secret", "amaze audience", "very issuer")
                .verifyIssuer(createSingletonJSONNode("iss", "very issuer"));
    }

    @Test(expected = JWTIssuerException.class)
    public void shouldFailIssuer() throws Exception {
        new JWTVerifier("such secret", "amaze audience", "very issuer")
                .verifyIssuer(createSingletonJSONNode("iss", "wow"));
    }

    @Test
    public void shouldVerifyIssuerWhenNotFoundInClaimsSet() throws Exception {
        new JWTVerifier("such secret", "amaze audience", "very issuer")
                .verifyIssuer(new HashMap<>());
    }

    @Test
    public void shouldVerifyAudience() throws Exception {
        new JWTVerifier("such secret", "amaze audience")
                .verifyAudience(createSingletonJSONNode("aud", "amaze audience"));
    }

    @Test(expected = JWTAudienceException.class)
    public void shouldFailAudience() throws Exception {
        new JWTVerifier("such secret", "amaze audience")
                .verifyAudience(createSingletonJSONNode("aud", "wow"));
    }

    @Test
    public void shouldVerifyAudienceWhenNotFoundInClaimsSet() throws Exception {
        new JWTVerifier("such secret", "amaze audience")
                .verifyAudience(new HashMap<>());
    }

    @Test
    public void shouldVerifyNullAudience() throws Exception {
        new JWTVerifier("such secret")
                .verifyAudience(createSingletonJSONNode("aud", "wow"));
    }

    @Test
    public void shouldVerifyArrayAudience() throws Exception {
        new JWTVerifier("such secret", "amaze audience")
                .verifyAudience(createSingletonJSONNode("aud",Lists.list("foo","amaze audience")));
    }
    
    @Test(expected = JWTAudienceException.class)
    public void shouldFailArrayAudience() throws Exception {
        new JWTVerifier("such secret", "amaze audience")
                .verifyAudience(createSingletonJSONNode("aud",Lists.list("foo")));
    }
    
    @Test
    public void decodeAndParse() throws Exception {
		final JWTVerifier jwtVerifier = new JWTVerifier("secret", "audience");
		String encodedJSON = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("{\"some\": \"json\", \"number\": 123}".getBytes());		
		final Map<String,Object> decodedJSON = jwtVerifier.decodeAndParse(encodedJSON);
        assertEquals("json", decodedJSON.get("some").toString());
        assertEquals(null, decodedJSON.get("unexisting_property"));
        assertEquals("123", decodedJSON.get("number").toString());
    }


    public static Map<String,Object> createSingletonJSONNode(String key, Object value) {
		Map<String,Object> jsonNode = new HashMap<>();
		jsonNode.put(key, value);
        return jsonNode;
    }

    public static Map<String,Object> createSingletonJSONNode(String key, List values) {
        final Map<String,Object>  jsonNodes =new HashMap<>();
        jsonNodes.put(key, values);
        return jsonNodes;
    }
}
