package com.auth0.jwt;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.SignatureException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.boon.Lists;

import static org.junit.Assert.assertEquals;

/**
 * General library JWTVerifier related unit tests
 */
public class JWTVerifierTest {
    
    public static Map<String,Object> createSingletonJSONNode(String key, Object value) {
		Map<String,Object> jsonNode = new HashMap<>();
		jsonNode.put(key, value);
        return jsonNode;
    }

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

	@Test(expected = IllegalArgumentException.class)
    public void constructorShouldFailOnEmptySecret() {
        new JWTVerifier("");
    }

    @Test
    public void shouldFailOn1Segments() throws Exception {
        expectedException.expect(IllegalStateException.class);
        signatureVerifier().verify("crypto");
    }

    @Test
    public void shouldFailOn2Segments() throws Exception {
        expectedException.expect(IllegalStateException.class);
        signatureVerifier().verify("much.crypto");
    }

    @Test
    public void shouldFailOn4Segments() throws Exception {
        expectedException.expect(IllegalStateException.class);
        signatureVerifier().verify("much.crypto.so.token");
    }

    @Test
    public void shouldFailOnEmptyStringToken() throws Exception {
        expectedException.expect(IllegalStateException.class);
        signatureVerifier().verify("");
    }

    @Test
    public void shouldFailOnNullToken() throws Exception {
        expectedException.expect(IllegalStateException.class);
        signatureVerifier().verify(null);
    }

    @Test
    public void shouldFailIfAlgorithmIsNotSetOnToken() throws Exception {
        expectedException.expect(IllegalStateException.class);
        new JWTVerifier("such secret").getAlgorithm(new HashMap<>());
    }

    @Test
    public void shouldFailIfAlgorithmIsNotSupported() throws Exception {
        expectedException.expect(JWTAlgorithmException.class);
        signatureVerifier().getAlgorithm(createSingletonJSONNode("alg", "doge-crypt"));
    }

    @Test
    public void shouldWorkIfAlgorithmIsSupported() throws Exception {
        signatureVerifier().getAlgorithm(createSingletonJSONNode("alg", "HS256"));
    }

    @Test
    public void shouldFailOnInvalidSignature() throws Exception {
        expectedException.expect(SignatureException.class);
        final String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                "." +
                "suchsignature_plzvalidate_zomgtokens";
        String secret = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
        signatureVerifier(secret).verifySignature(jws.split("\\."), Algorithm.HS256);
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
                .verifySignature(jws.split("\\."), Algorithm.HS256);
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
        signatureVerifier().verifyExpiration(
              createSingletonJSONNode("exp", System.currentTimeMillis() / 1000L + 50L));
    }

    @Test
    public void shouldVerifyExpirationString() throws Exception {
        new JWTVerifier("such secret").verifyExpiration(
                createSingletonJSONNode("exp", Long.toString(System.currentTimeMillis() / 1000L + 50L)));
    }

    @Test
    public void shouldVerifyIssuer() throws Exception {
        issuerVerifier("very issuer")
                .verifyIssuer(createSingletonJSONNode("iss", "very issuer"));
    }

    @Test
    public void shouldFailIssuer() throws Exception {
        expectedException.expect(JWTIssuerException.class);
        issuerVerifier("very issuer")
                .verifyIssuer(createSingletonJSONNode("iss", "wow"));
    }

    @Test
    public void shouldVerifyIssuerWhenNotFoundInClaimsSet() throws Exception {
    }

    @Test
    public void shouldVerifyAudience() throws Exception {
        audienceVerifier("amaze audience")
                .verifyAudience(createSingletonJSONNode("aud", "amaze audience"));
    }

    @Test(expected = JWTAudienceException.class)
    public void shouldFailAudience() throws Exception {
        audienceVerifier("amaze audience")
                .verifyAudience(createSingletonJSONNode("aud", "wow"));
    }

    @Test(expected = JWTIssuerException.class)
    public void shouldVerifyAudienceWhenNotFoundInClaimsSet() throws Exception {
        new JWTVerifier("such secret", "amaze audience", "very issuer")
                .verifyIssuer(new HashMap<>());
    }

    @Test
    public void shouldVerifyNullAudience() throws Exception {
        signatureVerifier()
                .verifyAudience(createSingletonJSONNode("aud", "wow"));
    }

    @Test(expected = JWTAudienceException.class)
    public void shouldVerifyArrayAudience() throws Exception {
        new JWTVerifier("such secret", "amaze audience")
                .verifyAudience(new HashMap<>());
    }

    @Test
    public void shouldFailArrayAudience() throws Exception {
        new JWTVerifier("such secret", "amaze audience")
                .verifyAudience(createSingletonJSONNode("aud",Lists.list("foo","amaze audience")));
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

    @Test
    public void shouldVerifyAudienceFromToken() throws Exception {
        expectedException.expect(JWTAudienceException.class);
        JWTVerifier verifier = new JWTVerifier("I.O.U a secret", "samples-api", null);
        verifier.verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.wLlz9xDltxqKHQC7BeauPi5Q4KQK4nDjlRqQPvKVLYk");
    }

    @Test
    public void shouldVerifyIssuerFromToken() throws Exception {
        expectedException.expect(JWTIssuerException.class);
        JWTVerifier verifier = new JWTVerifier("I.O.U a secret", null, "samples.auth0.com");
        verifier.verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.wLlz9xDltxqKHQC7BeauPi5Q4KQK4nDjlRqQPvKVLYk");
    }

    private static JWTVerifier signatureVerifier() {
        return new JWTVerifier("such secret");
    }

    private static JWTVerifier signatureVerifier(String secret) {
        return new JWTVerifier(secret);
    }

    private static JWTVerifier signatureVerifier(byte[] secret) {
        return new JWTVerifier(secret);
    }

    private static JWTVerifier issuerVerifier(String issuer) {
        return new JWTVerifier("such secret", null, issuer);
    }

    private static JWTVerifier audienceVerifier(String audience) {
        return new JWTVerifier("such secret", audience);
    }


}
