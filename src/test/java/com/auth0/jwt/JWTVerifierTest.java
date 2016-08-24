package com.auth0.jwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.codec.binary.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.SignatureException;

import static org.junit.Assert.assertEquals;

/**
 * General library JWTVerifier related unit tests
 */
public class JWTVerifierTest {

    private static final Base64 decoder = new Base64(true);

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void constructorShouldFailOnEmptySecret() {
        expectedException.expect(IllegalArgumentException.class);
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
        signatureVerifier().getAlgorithm(JsonNodeFactory.instance.objectNode());
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
        byte[] secret = decoder.decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");
        signatureVerifier(secret)
                .verifySignature(jws.split("\\."), Algorithm.HS256);
    }

    @Test
    public void shouldFailWithJwtThaHasTamperedAlgorithm() throws Exception {
        expectedException.expect(IllegalStateException.class);
        String tamperedAlg = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.QRsN2SlYJ3EEn7P9dnZGsq9tjyv3giOWzZJzhy67zZs";
        byte[] secret = decoder.decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");
        JWTVerifier verifier = new JWTVerifier(secret);
        verifier.verify(tamperedAlg);
    }

    @Test
    public void shouldFailWhenExpired1SecondAgo() throws Exception {
        expectedException.expect(JWTExpiredException.class);
        signatureVerifier().verifyExpiration(
                createSingletonJSONNode("exp", Long.toString(System.currentTimeMillis() / 1000L - 1L)));
    }

    @Test
    public void shouldVerifyExpiration() throws Exception {
        signatureVerifier().verifyExpiration(
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
        expectedException.expect(JWTIssuerException.class);
        issuerVerifier("very issuer")
                .verifyIssuer(JsonNodeFactory.instance.objectNode());
    }

    @Test
    public void shouldVerifyAudience() throws Exception {
        audienceVerifier("amaze audience")
                .verifyAudience(createSingletonJSONNode("aud", "amaze audience"));
    }

    @Test
    public void shouldFailAudience() throws Exception {
        expectedException.expect(JWTAudienceException.class);
        audienceVerifier("amaze audience")
                .verifyAudience(createSingletonJSONNode("aud", "wow"));
    }

    @Test
    public void shouldVerifyAudienceWhenNotFoundInClaimsSet() throws Exception {
        expectedException.expect(JWTAudienceException.class);
        audienceVerifier("amaze audience")
                .verifyAudience(JsonNodeFactory.instance.objectNode());
    }

    @Test
    public void shouldVerifyNullAudience() throws Exception {
        signatureVerifier()
                .verifyAudience(createSingletonJSONNode("aud", "wow"));
    }

    @Test
    public void shouldVerifyArrayAudience() throws Exception {
        audienceVerifier("amaze audience")
                .verifyAudience(createSingletonJSONNode("aud",
                        new ObjectMapper().readValue("[ \"foo\", \"amaze audience\" ]", ArrayNode.class)));
    }

    @Test
    public void shouldFailArrayAudience() throws Exception {
        expectedException.expect(JWTAudienceException.class);
        audienceVerifier("amaze audience")
                .verifyAudience(createSingletonJSONNode("aud",
                        new ObjectMapper().readValue("[ \"foo\" ]", ArrayNode.class)));
    }

    @Test
    public void decodeAndParse() throws Exception {
        final Base64 encoder = new Base64(true);
        final String encodedJSON = new String(encoder.encode("{\"some\": \"json\", \"number\": 123}".getBytes()));
        final JWTVerifier jwtVerifier = new JWTVerifier("secret", "audience");

        final JsonNode decodedJSON = jwtVerifier.decodeAndParse(encodedJSON);

        assertEquals("json", decodedJSON.get("some").asText());
        assertEquals(null, decodedJSON.get("unexisting_property"));
        assertEquals("123", decodedJSON.get("number").asText());
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

    private static JsonNode createSingletonJSONNode(String key, String value) {
        final ObjectNode jsonNodes = JsonNodeFactory.instance.objectNode();
        jsonNodes.put(key, value);
        return jsonNodes;
    }

    private static JsonNode createSingletonJSONNode(String key, JsonNode value) {
        final ObjectNode jsonNodes = JsonNodeFactory.instance.objectNode();
        jsonNodes.put(key, value);
        return jsonNodes;
    }
}
