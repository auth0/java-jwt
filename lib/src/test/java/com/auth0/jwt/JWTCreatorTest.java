package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import org.apache.commons.codec.binary.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;

public class JWTCreatorTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldThrowWhenRequestingSignWithoutAlgorithm() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Algorithm cannot be null");
        JWTCreator.init()
                .sign(null);
    }

    @SuppressWarnings("Convert2Diamond")
    @Test
    public void shouldAddHeaderClaim() throws Exception {
        Map<String, Object> header = new HashMap<String, Object>();
        header.put("asd", 123);
        String signed = JWTCreator.init()
                .withHeader(header)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("asd", 123));
    }

    @Test
    public void shouldAddKeyId() throws Exception {
        String signed = JWTCreator.init()
                .withKeyId("56a8bd44da435300010000015f5ed")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("kid", "56a8bd44da435300010000015f5ed"));
    }

    @Test
    public void shouldAddIssuer() throws Exception {
        String signed = JWTCreator.init()
                .withIssuer("auth0")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJpc3MiOiJhdXRoMCJ9"));
    }

    @Test
    public void shouldAddSubject() throws Exception {
        String signed = JWTCreator.init()
                .withSubject("1234567890")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJzdWIiOiIxMjM0NTY3ODkwIn0"));
    }

    @Test
    public void shouldAddAudience() throws Exception {
        String signed = JWTCreator.init()
                .withAudience("Mark")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJhdWQiOiJNYXJrIn0"));


        String signedArr = JWTCreator.init()
                .withAudience("Mark", "David")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signedArr, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signedArr)[1], is("eyJhdWQiOlsiTWFyayIsIkRhdmlkIl19"));
    }

    @Test
    public void shouldAddExpiresAt() throws Exception {
        String signed = JWTCreator.init()
                .withExpiresAt(new Date(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJleHAiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddNotBefore() throws Exception {
        String signed = JWTCreator.init()
                .withNotBefore(new Date(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJuYmYiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddIssuedAt() throws Exception {
        String signed = JWTCreator.init()
                .withIssuedAt(new Date(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJpYXQiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddJWTId() throws Exception {
        String signed = JWTCreator.init()
                .withJWTId("jwt_id_123")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJqdGkiOiJqd3RfaWRfMTIzIn0"));
    }

    @Test
    public void shouldRemoveClaimWhenPassingNull() throws Exception {
        String signed = JWTCreator.init()
                .withIssuer("iss")
                .withIssuer(null)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("e30"));
    }

    @Test
    public void shouldSetCorrectAlgorithmInTheHeader() throws Exception {
        String signed = JWTCreator.init()
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("alg", "HS256"));
    }

    @Test
    public void shouldSetCorrectTypeInTheHeader() throws Exception {
        String signed = JWTCreator.init()
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("typ", "JWT"));
    }

    @Test
    public void shouldSetEmptySignatureIfAlgorithmIsNone() throws Exception {
        String signed = JWTCreator.init()
                .sign(Algorithm.none());
        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[2], is(""));
    }

    @Test
    public void shouldThrowOnNullCustomClaimName() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Custom Claim's name can't be null.");
        JWTCreator.init()
                .withClaim(null, "value");
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeString() throws Exception {
        String jwt = JWTCreator.init()
                .withClaim("name", "value")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjoidmFsdWUifQ"));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeInteger() throws Exception {
        String jwt = JWTCreator.init()
                .withClaim("name", 123)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjoxMjN9"));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeDouble() throws Exception {
        String jwt = JWTCreator.init()
                .withClaim("name", 23.45)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjoyMy40NX0"));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeBoolean() throws Exception {
        String jwt = JWTCreator.init()
                .withClaim("name", true)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjp0cnVlfQ"));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeDate() throws Exception {
        Date date = new Date(1478891521000L);
        String jwt = JWTCreator.init()
                .withClaim("name", date)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjoxNDc4ODkxNTIxfQ"));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeObject() throws Exception {
        String jwt = JWTCreator.init()
                .withClaim("name", new FooBar("bar"))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjp7ImZvbyI6ImJhciJ9fQ"));
    }

    @Test
    public void shouldAcceptCustomArrayClaimOfTypeString() throws Exception {
        String jwt = JWTCreator.init()
                .withArrayClaim("name", new String[]{"text", "123", "true"})
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjpbInRleHQiLCIxMjMiLCJ0cnVlIl19"));
    }

    @Test
    public void shouldAcceptCustomArrayClaimOfTypeInteger() throws Exception {
        String jwt = JWTCreator.init()
                .withArrayClaim("name", new Integer[]{1, 2, 3})
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjpbMSwyLDNdfQ"));
    }

    private static class FooBar {
        private final String foo;

        private FooBar(String foo) {
            this.foo = foo;
        }

        public String getFoo() {
            return foo;
        }
    }
}