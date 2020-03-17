package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.ECDSAKeyProvider;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.*;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JWTCreatorTest {
    private static final String PRIVATE_KEY_FILE_RSA = "src/test/resources/rsa-private.pem";
    private static final String PRIVATE_KEY_FILE_EC_256 = "src/test/resources/ec256-key-private.pem";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldThrowWhenRequestingSignWithoutAlgorithm() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Algorithm cannot be null");
        JWTCreator.init()
                .sign(null);
    }

    @SuppressWarnings("Convert2Diamond")
    @Test
    public void shouldAddHeaderClaim() {
        Map<String, Object> header = new HashMap<String, Object>();
        header.put("asd", 123);
        String signed = JWTCreator.init()
                .withHeader(header)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("asd", 123));
    }

    @Test
    public void shouldReturnBuilderIfNullMapIsProvided() {
        String signed = JWTCreator.init()
                                  .withHeader(null)
                                  .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
    }

    @Test
    public void shouldOverwriteExistingHeaderIfHeaderMapContainsTheSameKey() {
        Map<String, Object> header = new HashMap<String, Object>();
        header.put(PublicClaims.KEY_ID, "xyz");

        String signed = JWTCreator.init()
                                  .withKeyId("abc")
                                  .withHeader(header)
                                  .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry(PublicClaims.KEY_ID, "xyz"));
    }

    @Test
    public void shouldOverwriteExistingHeadersWhenSettingSameHeaderKey() {
        Map<String, Object> header = new HashMap<String, Object>();
        header.put(PublicClaims.KEY_ID, "xyz");

        String signed = JWTCreator.init()
                                  .withHeader(header)
                                  .withKeyId("abc")
                                  .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry(PublicClaims.KEY_ID, "abc"));
    }

    @Test
    public void shouldRemoveHeaderIfTheValueIsNull() {
        Map<String, Object> header = new HashMap<String, Object>();
        header.put(PublicClaims.KEY_ID, null);
        header.put("test2", "isSet");

        String signed = JWTCreator.init()
                                  .withKeyId("test")
                                  .withHeader(header)
                                  .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.isNotPresent(PublicClaims.KEY_ID));
        assertThat(headerJson, JsonMatcher.hasEntry("test2", "isSet"));
    }

    @Test
    public void shouldAddKeyId() {
        String signed = JWTCreator.init()
                .withKeyId("56a8bd44da435300010000015f5ed")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("kid", "56a8bd44da435300010000015f5ed"));
    }

    @Test
    public void shouldAddKeyIdIfAvailableFromRSAAlgorithms() throws Exception {
        RSAPrivateKey privateKey = (RSAPrivateKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_RSA, "RSA");
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        when(provider.getPrivateKeyId()).thenReturn("my-key-id");
        when(provider.getPrivateKey()).thenReturn(privateKey);

        String signed = JWTCreator.init()
                .sign(Algorithm.RSA256(provider));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("kid", "my-key-id"));
    }

    @Test
    public void shouldNotOverwriteKeyIdIfAddedFromRSAAlgorithms() throws Exception {
        RSAPrivateKey privateKey = (RSAPrivateKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_RSA, "RSA");
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        when(provider.getPrivateKeyId()).thenReturn("my-key-id");
        when(provider.getPrivateKey()).thenReturn(privateKey);

        String signed = JWTCreator.init()
                .withKeyId("real-key-id")
                .sign(Algorithm.RSA256(provider));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("kid", "my-key-id"));
    }

    @Test
    public void shouldAddKeyIdIfAvailableFromECDSAAlgorithms() throws Exception {
        ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_EC_256, "EC");
        ECDSAKeyProvider provider = mock(ECDSAKeyProvider.class);
        when(provider.getPrivateKeyId()).thenReturn("my-key-id");
        when(provider.getPrivateKey()).thenReturn(privateKey);

        String signed = JWTCreator.init()
                .sign(Algorithm.ECDSA256(provider));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("kid", "my-key-id"));
    }

    @Test
    public void shouldNotOverwriteKeyIdIfAddedFromECDSAAlgorithms() throws Exception {
        ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_EC_256, "EC");
        ECDSAKeyProvider provider = mock(ECDSAKeyProvider.class);
        when(provider.getPrivateKeyId()).thenReturn("my-key-id");
        when(provider.getPrivateKey()).thenReturn(privateKey);

        String signed = JWTCreator.init()
                .withKeyId("real-key-id")
                .sign(Algorithm.ECDSA256(provider));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("kid", "my-key-id"));
    }

    @Test
    public void shouldAddIssuer() {
        String signed = JWTCreator.init()
                .withIssuer("auth0")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJpc3MiOiJhdXRoMCJ9"));
    }

    @Test
    public void shouldAddSubject() {
        String signed = JWTCreator.init()
                .withSubject("1234567890")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJzdWIiOiIxMjM0NTY3ODkwIn0"));
    }

    @Test
    public void shouldAddAudience() {
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
    public void shouldAddExpiresAtAsInstant() {
        String signed = JWTCreator.init()
                .withExpiresAt(Instant.ofEpochMilli(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJleHAiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddExpiresAtAsDate() {
        String signed = JWTCreator.init()
                .withExpiresAt(new Date(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJleHAiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddNotBeforeAsInstant() {
        String signed = JWTCreator.init()
                .withNotBefore(Instant.ofEpochMilli(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJuYmYiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddNotBeforeAsDate() {
        String signed = JWTCreator.init()
                .withNotBefore(new Date(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJuYmYiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddIssuedAtAsInstant() {
        String signed = JWTCreator.init()
                .withIssuedAt(Instant.ofEpochMilli(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJpYXQiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddIssuedAtAsDate() {
        String signed = JWTCreator.init()
                .withIssuedAt(new Date(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJpYXQiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddJWTId() {
        String signed = JWTCreator.init()
                .withJWTId("jwt_id_123")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJqdGkiOiJqd3RfaWRfMTIzIn0"));
    }

    @Test
    public void shouldRemoveClaimWhenPassingNull() {
        String signed = JWTCreator.init()
                .withIssuer("iss")
                .withIssuer(null)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("e30"));
    }

    @Test
    public void shouldSetCorrectAlgorithmInTheHeader() {
        String signed = JWTCreator.init()
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("alg", "HS256"));
    }

    @Test
    public void shouldSetDefaultTypeInTheHeader() {
        String signed = JWTCreator.init()
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("typ", "JWT"));
    }

    @Test
    public void shouldSetCustomTypeInTheHeader() {
        Map<String, Object> header = Collections.singletonMap("typ", "passport");
        String signed = JWTCreator.init()
                .withHeader(header)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("typ", "passport"));
    }

    @Test
    public void shouldSetEmptySignatureIfAlgorithmIsNone() {
        String signed = JWTCreator.init()
                .sign(Algorithm.none());
        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[2], is(""));
    }

    @Test
    public void shouldThrowOnNullCustomClaimName() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Custom Claim's name can't be null.");
        JWTCreator.init()
                .withClaim(null, "value");
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeString() {
        String jwt = JWTCreator.init()
                .withClaim("name", "value")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjoidmFsdWUifQ"));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeInteger() {
        String jwt = JWTCreator.init()
                .withClaim("name", 123)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjoxMjN9"));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeLong() {
        String jwt = JWTCreator.init()
                .withClaim("name", Long.MAX_VALUE)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjo5MjIzMzcyMDM2ODU0Nzc1ODA3fQ"));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeDouble() {
        String jwt = JWTCreator.init()
                .withClaim("name", 23.45)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjoyMy40NX0"));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeBoolean() {
        String jwt = JWTCreator.init()
                .withClaim("name", true)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjp0cnVlfQ"));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeInstant() {
        Instant instant = Instant.ofEpochMilli(1478891521000L);
        String jwt = JWTCreator.init()
                .withClaim("name", instant)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjoxNDc4ODkxNTIxfQ"));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeDate() {
        Date date = new Date(1478891521000L);
        String jwt = JWTCreator.init()
                .withClaim("name", date)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjoxNDc4ODkxNTIxfQ"));
    }

    @Test
    public void shouldAcceptCustomArrayClaimOfTypeString() {
        String jwt = JWTCreator.init()
                .withArrayClaim("name", new String[]{"text", "123", "true"})
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjpbInRleHQiLCIxMjMiLCJ0cnVlIl19"));
    }

    @Test
    public void shouldAcceptCustomArrayClaimOfTypeInteger() {
        String jwt = JWTCreator.init()
                .withArrayClaim("name", new Integer[]{1, 2, 3})
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjpbMSwyLDNdfQ"));
    }

    @Test
    public void shouldAcceptCustomArrayClaimOfTypeLong() {
        String jwt = JWTCreator.init()
                .withArrayClaim("name", new Long[]{1L, 2L, 3L})
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjpbMSwyLDNdfQ"));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeMap() {
        Map<String, Object> data = new HashMap<>();
        data.put("test1", "abc");
        data.put("test2", "def");
        String jwt = JWTCreator.init()
                .withClaim("data", data)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJkYXRhIjp7InRlc3QyIjoiZGVmIiwidGVzdDEiOiJhYmMifX0"));
    }

    @Test
    public void shouldRefuseCustomClaimOfTypeUserPojo() {
        Map<String, Object> data = new HashMap<>();
        data.put("test1", new UserPojo("Michael", 255));

        exception.expect(IllegalArgumentException.class);

        JWTCreator.init()
                 .withClaim("pojo", data)
                 .sign(Algorithm.HMAC256("secret"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void shouldAcceptCustomMapClaimOfBasicObjectTypes() throws Exception {
        Map<String, Object> data = new HashMap<>();

        // simple types
        data.put("string", "abc");
        data.put("integer", 1);
        data.put("long", Long.MAX_VALUE);
        data.put("double", 123.456d);
        data.put("date", new Date(123000));
        data.put("instant", Instant.ofEpochSecond(123L));
        data.put("boolean", true);

        // array types
        data.put("intArray", new Integer[]{3, 5});
        data.put("longArray", new Long[]{Long.MAX_VALUE, Long.MIN_VALUE});
        data.put("stringArray", new String[]{"string"});

        data.put("list", Arrays.asList("a", "b", "c", Instant.ofEpochSecond(41L)));

        Map<String, Object> sub = new HashMap<>();
        sub.put("subKey", "subValue");
        sub.put("subDate", new Date(567000));
        sub.put("subInstant", Instant.ofEpochSecond(567L));
        data.put("map", sub);

        String jwt = JWTCreator.init()
                .withClaim("data", data)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");

        DecodedJWT decodedJWT = JWT.decode(jwt);
        Map<String, Object> map = decodedJWT.getClaim("data").asMap();

        assertThat(map.get("string"), is("abc"));
        assertThat(map.get("integer"), is(1));
        assertThat(map.get("long"), is(Long.MAX_VALUE));
        assertThat(map.get("double"), is(123.456d));
        assertThat(map.get("date"), is(123));
        assertThat(map.get("instant"), is(123));
        assertThat(map.get("boolean"), is(true));

        // array types
        assertThat(map.get("intArray"), is(Arrays.asList(3, 5)));
        assertThat(map.get("longArray"), is(Arrays.asList(Long.MAX_VALUE, Long.MIN_VALUE)));
        assertThat(map.get("stringArray"), is(Arrays.asList("string")));

        // list
        assertThat(map.get("list"), is(Arrays.asList("a", "b", "c", 41)));

        // nested map
        Map nested = (Map) map.get("map");
        assertThat(nested.get("subKey"), is("subValue"));
        assertThat(nested.get("subDate"), is(567));
        assertThat(nested.get("subInstant"), is(567));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void shouldAcceptCustomListClaimOfBasicObjectTypes() throws Exception {
        List<Object> data = new ArrayList<>();

        // simple types
        data.add("abc");
        data.add(1);
        data.add(Long.MAX_VALUE);
        data.add(123.456d);
        data.add(new Date(123000));
        data.add(Instant.ofEpochSecond(123L));
        data.add(true);
        
        // array types
        data.add(new Integer[]{3, 5});
        data.add(new Long[]{Long.MAX_VALUE, Long.MIN_VALUE});
        data.add(new String[]{"string"});

        data.add(Arrays.asList("a", "b", "c"));

        Map<String, Object> sub = new HashMap<>();
        sub.put("subKey", "subValue");
        sub.put("subDate", new Date(567000));
        sub.put("subInstant", Instant.ofEpochSecond(567L));

        data.add(sub);

        String jwt = JWTCreator.init()
                .withClaim("data", data)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");

        DecodedJWT decodedJWT = JWT.decode(jwt);
        List<Object> list = decodedJWT.getClaim("data").asList(Object.class);
        
        assertThat(list.get(0), is("abc"));
        assertThat(list.get(1), is(1));
        assertThat(list.get(2), is(Long.MAX_VALUE));
        assertThat(list.get(3), is(123.456d));
        assertThat(list.get(4), is(123));
        assertThat(list.get(5), is(123));
        assertThat(list.get(6), is(true));
        
        // array types
        assertThat(list.get(7), is(Arrays.asList(new Integer[]{3, 5})));
        assertThat(list.get(8), is(Arrays.asList(new Long[]{Long.MAX_VALUE, Long.MIN_VALUE})));
        assertThat(list.get(9), is(Arrays.asList(new String[]{"string"})));

        // list
        assertThat(list.get(10), is(Arrays.asList("a", "b", "c")));

        // nested map
        Map nested = (Map) list.get(11);
        assertThat(nested.get("subKey"), is("subValue"));
        assertThat(nested.get("subDate"), is(567));
        assertThat(nested.get("subInstant"), is(567));
    }

    @Test
    public void shouldAcceptCustomClaimForNullListItem() {
        Map<String, Object> data = new HashMap<>();
        data.put("test1", Arrays.asList("a", null, "c"));
        
        JWTCreator.init()
                 .withClaim("pojo", data)
                 .sign(Algorithm.HMAC256("secret"));
    }

    @Test
    public void shouldRefuseCustomClaimForNullMapValue() {
        Map<String, Object> data = new HashMap<>();
        data.put("subKey", null);
        
        exception.expect(IllegalArgumentException.class);

        JWTCreator.init()
                 .withClaim("pojo", data)
                 .sign(Algorithm.HMAC256("secret"));
    }

    @Test
    public void shouldRefuseCustomClaimForNullMapKey() {
        Map<String, Object> data = new HashMap<>();
        data.put(null, "subValue");
        
        exception.expect(IllegalArgumentException.class);

        JWTCreator.init()
                 .withClaim("pojo", data)
                 .sign(Algorithm.HMAC256("secret"));
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    @Test
    public void shouldRefuseCustomMapClaimForNonStringKey() {
        Map data = new HashMap<>();
        data.put(new Object(), "value");
        
        exception.expect(IllegalArgumentException.class);

        JWTCreator.init()
                 .withClaim("pojo", (Map<String, Object>)data)
                 .sign(Algorithm.HMAC256("secret"));
    }

    @Test
    public void shouldRefuseCustomListClaimForUnknownListElement() {
        List<Object> list = Arrays.asList(new UserPojo("Michael", 255));

        exception.expect(IllegalArgumentException.class);

        JWTCreator.init()
                 .withClaim("list", list)
                 .sign(Algorithm.HMAC256("secret"));
    }

    @Test
    public void shouldRefuseCustomListClaimForUnknownListElementWrappedInAMap() {
        List<Object> list = Arrays.asList(new UserPojo("Michael", 255));
        
        Map<String, Object> data = new HashMap<>();
        data.put("someList", list);

        exception.expect(IllegalArgumentException.class);

        JWTCreator.init()
                 .withClaim("list", list)
                 .sign(Algorithm.HMAC256("secret"));
    }

    @Test
    public void shouldRefuseCustomListClaimForUnknownArrayType() {
        List<Object> list = new ArrayList<>();
        list.add(new Object[] {"test"});

        exception.expect(IllegalArgumentException.class);

        JWTCreator.init()
                 .withClaim("list", list)
                 .sign(Algorithm.HMAC256("secret"));
    }
}
