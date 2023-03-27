package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.ECDSAKeyProvider;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertTrue;
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

    @Test
    public void shouldAddHeaderClaim() {
        Date date = new Date(123000);
        Instant instant = date.toInstant();

        List<Object> list = Arrays.asList(date, instant);
        Map<String, Object> map = new HashMap<>();
        map.put("date", date);
        map.put("instant", instant);

        List<Object> expectedSerializedList = Arrays.asList(date.getTime() / 1000, instant.getEpochSecond());
        Map<String, Object> expectedSerializedMap = new HashMap<>();
        expectedSerializedMap.put("date", date.getTime() / 1000);
        expectedSerializedMap.put("instant", instant.getEpochSecond());

        Map<String, Object> header = new HashMap<>();
        header.put("string", "string");
        header.put("int", 42);
        header.put("long", 4200000000L);
        header.put("double", 123.123);
        header.put("bool", true);
        header.put("date", date);
        header.put("instant", instant);
        header.put("list", list);
        header.put("map", map);

        String signed = JWTCreator.init()
                .withHeader(header)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("string", "string"));
        assertThat(headerJson, JsonMatcher.hasEntry("int", 42));
        assertThat(headerJson, JsonMatcher.hasEntry("long", 4200000000L));
        assertThat(headerJson, JsonMatcher.hasEntry("double", 123.123));
        assertThat(headerJson, JsonMatcher.hasEntry("bool", true));
        assertThat(headerJson, JsonMatcher.hasEntry("date", 123));
        assertThat(headerJson, JsonMatcher.hasEntry("instant", 123));
        assertThat(headerJson, JsonMatcher.hasEntry("list", expectedSerializedList));
        assertThat(headerJson, JsonMatcher.hasEntry("map", expectedSerializedMap));
    }

    @Test
    public void shouldReturnBuilderIfNullMapIsProvided() {
        Map<String, Object> nullMap = null;
        String nullString = null;
        String signed = JWTCreator.init()
                .withHeader(nullMap)
                .withHeader(nullString)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
    }

    @Test
    public void shouldSupportJsonValueHeaderWithNestedDataStructure() {
        String stringClaim = "someClaim";
        Integer intClaim = 1;
        List<String> nestedListClaims = Arrays.asList("1", "2");
        String claimsJson = "{\"stringClaim\": \"someClaim\", \"intClaim\": 1, \"nestedClaim\": { \"listClaim\": [ \"1\", \"2\" ]}}";

        String jwt = JWTCreator.init()
                .withHeader(claimsJson)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);

        assertThat(headerJson, JsonMatcher.hasEntry("stringClaim", stringClaim));
        assertThat(headerJson, JsonMatcher.hasEntry("intClaim", intClaim));
        assertThat(headerJson, JsonMatcher.hasEntry("listClaim", nestedListClaims));
    }

    @Test
    public void shouldFailWithIllegalArgumentExceptionForInvalidJsonForHeaderClaims() {
        String invalidJson = "{ invalidJson }";

        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Invalid header JSON");

        JWTCreator.init()
                .withHeader(invalidJson)
                .sign(Algorithm.HMAC256("secret"));
    }

    @Test
    public void shouldOverwriteExistingHeaderIfHeaderMapContainsTheSameKey() {
        Map<String, Object> header = new HashMap<>();
        header.put(HeaderParams.KEY_ID, "xyz");

        String signed = JWTCreator.init()
                .withKeyId("abc")
                .withHeader(header)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry(HeaderParams.KEY_ID, "xyz"));
    }


    @Test
    public void shouldOverwriteExistingHeadersWhenSettingSameHeaderKey() {
        Map<String, Object> header = new HashMap<>();
        header.put(HeaderParams.KEY_ID, "xyz");

        String signed = JWTCreator.init()
                .withHeader(header)
                .withKeyId("abc")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry(HeaderParams.KEY_ID, "abc"));
    }

    @Test
    public void shouldRemoveHeaderIfTheValueIsNull() {
        Map<String, Object> header = new HashMap<>();
        header.put(HeaderParams.KEY_ID, null);
        header.put("test2", "isSet");

        String signed = JWTCreator.init()
                .withKeyId("test")
                .withHeader(header)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.isNotPresent(HeaderParams.KEY_ID));
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
    public void shouldAddExpiresAt() {
        String signed = JWTCreator.init()
                .withExpiresAt(new Date(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJleHAiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddExpiresAtInstant() {
        String signed = JWTCreator.init()
                .withExpiresAt(Instant.ofEpochSecond(1477592))
                .sign(Algorithm.HMAC256("secret"));

        System.out.println(signed);
        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJleHAiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddNotBefore() {
        String signed = JWTCreator.init()
                .withNotBefore(new Date(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJuYmYiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddNotBeforeInstant() {
        String signed = JWTCreator.init()
                .withNotBefore(Instant.ofEpochSecond(1477592))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJuYmYiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddIssuedAt() {
        String signed = JWTCreator.init()
                .withIssuedAt(new Date(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJpYXQiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddIssuedAtInstant() {
        String signed = JWTCreator.init()
                .withIssuedAt(Instant.ofEpochSecond(1477592))
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
    public void shouldAcceptCustomClaimOfTypeDateInstant() {
        Instant instant = Instant.ofEpochSecond(1478891521);
        String jwt = JWTCreator.init()
                .withClaim("name", instant)
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
        data.put("date", new Date(123000L));
        data.put("instant", Instant.ofEpochSecond(123));
        data.put("boolean", true);

        // array types
        data.put("intArray", new Integer[]{3, 5});
        data.put("longArray", new Long[]{Long.MAX_VALUE, Long.MIN_VALUE});
        data.put("stringArray", new String[]{"string"});

        data.put("list", Arrays.asList("a", "b", "c"));

        Map<String, Object> sub = new HashMap<>();
        sub.put("subKey", "subValue");

        data.put("map", sub);

        String jwt = JWTCreator.init()
                .withClaim("data", data)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");

        String body = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> map = (Map<String, Object>) mapper.readValue(body, Map.class).get("data");

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
        assertThat(map.get("stringArray"), is(Collections.singletonList("string")));

        // list
        assertThat(map.get("list"), is(Arrays.asList("a", "b", "c")));
        assertThat(map.get("map"), is(sub));

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
        data.add(new Date(123000L));
        data.add(Instant.ofEpochSecond(123));
        data.add(true);

        // array types
        data.add(new Integer[]{3, 5});
        data.add(new Long[]{Long.MAX_VALUE, Long.MIN_VALUE});
        data.add(new String[]{"string"});

        data.add(Arrays.asList("a", "b", "c"));

        Map<String, Object> sub = new HashMap<>();
        sub.put("subKey", "subValue");

        data.add(sub);

        String jwt = JWTCreator.init()
                .withClaim("data", data)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");

        String body = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        ObjectMapper mapper = new ObjectMapper();
        List<Object> list = (List<Object>) mapper.readValue(body, Map.class).get("data");

        assertThat(list.get(0), is("abc"));
        assertThat(list.get(1), is(1));
        assertThat(list.get(2), is(Long.MAX_VALUE));
        assertThat(list.get(3), is(123.456d));
        assertThat(list.get(4), is(123));
        assertThat(list.get(5), is(123));
        assertThat(list.get(6), is(true));

        // array types
        assertThat(list.get(7), is(Arrays.asList(3, 5)));
        assertThat(list.get(8), is(Arrays.asList(Long.MAX_VALUE, Long.MIN_VALUE)));
        assertThat(list.get(9), is(Arrays.asList("string")));

        // list
        assertThat(list.get(10), is(Arrays.asList("a", "b", "c")));
        assertThat(list.get(11), is(sub));
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
    public void shouldRefuseCustomClaimForNullMapKey() {
        Map<String, Object> data = new HashMap<>();
        data.put(null, "subValue");

        exception.expect(IllegalArgumentException.class);

        JWTCreator.init()
                .withClaim("pojo", data)
                .sign(Algorithm.HMAC256("secret"));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    public void shouldRefuseCustomMapClaimForNonStringKey() {
        Map data = new HashMap<>();
        data.put(new Object(), "value");

        exception.expect(IllegalArgumentException.class);

        JWTCreator.init()
                .withClaim("pojo", (Map<String, Object>) data)
                .sign(Algorithm.HMAC256("secret"));
    }

    @Test
    public void shouldRefuseCustomListClaimForUnknownListElement() {
        List<Object> list = Collections.singletonList(new UserPojo("Michael", 255));

        exception.expect(IllegalArgumentException.class);

        JWTCreator.init()
                .withClaim("list", list)
                .sign(Algorithm.HMAC256("secret"));
    }

    @Test
    public void shouldRefuseCustomListClaimForUnknownListElementWrappedInAMap() {
        List<Object> list = Collections.singletonList(new UserPojo("Michael", 255));

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
        list.add(new Object[]{"test"});

        exception.expect(IllegalArgumentException.class);

        JWTCreator.init()
                .withClaim("list", list)
                .sign(Algorithm.HMAC256("secret"));
    }

    @Test
    public void withPayloadShouldAddBasicClaim() {
        Map<String, Object> payload = new HashMap<>();
        payload.put("asd", 123);
        String jwt = JWTCreator.init()
                .withPayload(payload)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        assertThat(payloadJson, JsonMatcher.hasEntry("asd", 123));
    }

    @Test
    public void withPayloadShouldCreateJwtWithEmptyBodyIfPayloadNull() {
        Map<String, Object> nullMap = null;
        String nullString = null;
        String jwt = JWTCreator.init()
                .withPayload(nullMap)
                .withPayload(nullString)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        assertThat(payloadJson, is("{}"));
    }

    @Test
    public void withPayloadShouldOverwriteExistingClaimIfPayloadMapContainsTheSameKey() {
        Map<String, Object> payload = new HashMap<>();
        payload.put(HeaderParams.KEY_ID, "xyz");

        String jwt = JWTCreator.init()
                .withKeyId("abc")
                .withPayload(payload)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        assertThat(payloadJson, JsonMatcher.hasEntry(HeaderParams.KEY_ID, "xyz"));
    }

    @Test
    public void shouldOverwriteExistingPayloadWhenSettingSamePayloadKey() {
        Map<String, Object> payload = new HashMap<>();
        payload.put(RegisteredClaims.ISSUER, "xyz");

        String jwt = JWTCreator.init()
                .withPayload(payload)
                .withIssuer("abc")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        assertThat(payloadJson, JsonMatcher.hasEntry(RegisteredClaims.ISSUER, "abc"));
    }

    @Test
    public void withPayloadShouldNotAllowCustomType() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Claim values must only be of types Map, List, Boolean, Integer, Long, Double, String, Date, Instant, and Null");

        Map<String, Object> payload = new HashMap<>();
        payload.put("entry", "value");
        payload.put("pojo", new UserPojo("name", 42));
        JWTCreator.init()
                .withPayload(payload)
                .sign(Algorithm.HMAC256("secret"));
    }

    @Test
    public void withPayloadShouldAllowNullListItems() {
        Map<String, Object> payload = new HashMap<>();
        payload.put("list", Arrays.asList("item1", null, "item2"));
        String jwt = JWTCreator.init()
                .withPayload(payload)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        assertThat(payloadJson, JsonMatcher.hasEntry("list", Arrays.asList("item1", null, "item2")));
    }

    @Test
    public void withPayloadShouldNotAllowListWithCustomType() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Claim values must only be of types Map, List, Boolean, Integer, Long, Double, String, Date, Instant, and Null");

        Map<String, Object> payload = new HashMap<>();
        payload.put("list", Arrays.asList("item1", new UserPojo("name", 42)));
        JWTCreator.init()
                .withPayload(payload)
                .sign(Algorithm.HMAC256("secret"));
    }

    @Test
    public void withPayloadShouldNotAllowMapWithCustomType() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Claim values must only be of types Map, List, Boolean, Integer, Long, Double, String, Date, Instant, and Null");

        Map<String, Object> payload = new HashMap<>();
        payload.put("entry", "value");
        payload.put("map", Collections.singletonMap("pojo", new UserPojo("name", 42)));
        JWTCreator.init()
                .withPayload(payload)
                .sign(Algorithm.HMAC256("secret"));
    }

    @Test
    public void withPayloadShouldAllowNestedSupportedTypes() {
        /*
        JWT:
        {
          "stringClaim": "string",
          "intClaim": 41,
          "listClaim": [
            1, 2, {
              "nestedObjKey": true
            }
          ],
          "objClaim": {
            "objKey": ["nestedList1", "nestedList2"]
          }
        }
         */

        List<?> listClaim = Arrays.asList(1, 2, Collections.singletonMap("nestedObjKey", "nestedObjValue"));
        Map<String, Object> mapClaim = new HashMap<>();
        mapClaim.put("objKey", Arrays.asList("nestedList1", true));

        Map<String, Object> payload = new HashMap<>();
        payload.put("stringClaim", "string");
        payload.put("intClaim", 41);
        payload.put("listClaim", listClaim);
        payload.put("objClaim", mapClaim);

        String jwt = JWTCreator.init()
                .withPayload(payload)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        assertThat(payloadJson, JsonMatcher.hasEntry("stringClaim", "string"));
        assertThat(payloadJson, JsonMatcher.hasEntry("intClaim", 41));
        assertThat(payloadJson, JsonMatcher.hasEntry("listClaim", listClaim));
        assertThat(payloadJson, JsonMatcher.hasEntry("objClaim", mapClaim));
    }

    @Test
    public void withPayloadShouldSupportNullValuesEverywhere() {
         /*
        JWT:
            {
              "listClaim": [
                "answer to ultimate question of life",
                42,
                null
              ],
              "claim": null,
              "listNestedClaim": [
                1,
                2,
                {
                  "nestedObjKey": null
                }
              ],
              "objClaim": {
                "nestedObjKey": null,
                "objObjKey": {
                  "nestedObjKey": null,
                  "objListKey": [
                    null,
                    "nestedList2"
                  ]
                },
                "objListKey": [
                  null,
                  "nestedList2"
                ]
              }
            }
         */

        List<?> listClaim = Arrays.asList("answer to ultimate question of life", 42, null);
        List<?> listNestedClaim = Arrays.asList(1, 2, Collections.singletonMap("nestedObjKey", null));
        List<?> objListKey = Arrays.asList(null, "nestedList2");
        HashMap<String, Object> objClaim = new HashMap<>();
        objClaim.put("nestedObjKey", null);
        objClaim.put("objListKey", objListKey);
        objClaim.put("objObjKey", new HashMap<>(objClaim));


        Map<String, Object> payload = new HashMap<>();
        payload.put("claim", null);
        payload.put("listClaim", listClaim);
        payload.put("listNestedClaim", listNestedClaim);
        payload.put("objClaim", objClaim);

        String jwt = JWTCreator.init()
                .withPayload(payload)
                .withHeader(payload)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);

        assertThat(payloadJson, JsonMatcher.hasEntry("claim", null));
        assertThat(payloadJson, JsonMatcher.hasEntry("listClaim", listClaim));
        assertThat(payloadJson, JsonMatcher.hasEntry("listNestedClaim", listNestedClaim));
        assertThat(payloadJson, JsonMatcher.hasEntry("objClaim", objClaim));

        assertThat(headerJson, JsonMatcher.hasEntry("claim", null));
        assertThat(headerJson, JsonMatcher.hasEntry("listClaim", listClaim));
        assertThat(headerJson, JsonMatcher.hasEntry("listNestedClaim", listNestedClaim));
        assertThat(headerJson, JsonMatcher.hasEntry("objClaim", objClaim));
    }

    @Test
    public void withPayloadShouldSupportJsonValueWithNestedDataStructure() {
        String stringClaim = "someClaim";
        Integer intClaim = 1;
        List<String> nestedListClaims = Arrays.asList("1", "2");
        String claimsJson = "{\"stringClaim\": \"someClaim\", \"intClaim\": 1, \"nestedClaim\": { \"listClaim\": [ \"1\", \"2\" ]}}";

        String jwt = JWTCreator.init()
                .withPayload(claimsJson)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);

        assertThat(payloadJson, JsonMatcher.hasEntry("stringClaim", stringClaim));
        assertThat(payloadJson, JsonMatcher.hasEntry("intClaim", intClaim));
        assertThat(payloadJson, JsonMatcher.hasEntry("listClaim", nestedListClaims));
    }

    @Test
    public void shouldFailWithIllegalArgumentExceptionForInvalidJsonForPayloadClaims() {
        String invalidJson = "{ invalidJson }";

        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Invalid payload JSON");

        JWTCreator.init()
                .withPayload(invalidJson)
                .sign(Algorithm.HMAC256("secret"));
    }

    @Test
    public void shouldCreatePayloadWithNullForMap() {
        String jwt = JWTCreator.init()
                .withClaim("name", (Map<String, ?>) null)
                .sign(Algorithm.HMAC256("secret"));
        assertThat(jwt, is(notNullValue()));
        assertTrue(JWT.decode(jwt).getClaim("name").isNull());
    }

    @Test
    public void shouldCreatePayloadWithNullForList() {
        String jwt = JWTCreator.init()
                .withClaim("name", (List<?>) null)
                .sign(Algorithm.HMAC256("secret"));
        assertThat(jwt, is(notNullValue()));
        assertTrue(JWT.decode(jwt).getClaim("name").isNull());
    }

    @Test
    public void shouldPreserveInsertionOrder() throws Exception {
        String taxonomyJson = "{\"class\": \"mammalia\", \"order\": \"carnivora\", \"family\": \"canidae\", \"genus\": \"vulpes\"}";
        List<String> taxonomyClaims = Arrays.asList("class", "order", "family", "genus");
        List<String> headerInsertionOrder = new ArrayList<>(taxonomyClaims);
        Map<String, Object> header = new LinkedHashMap<>();
        for (int i = 0; i < 10; i++) {
            String key = "h" + i;
            header.put(key, "v" + 1);
            headerInsertionOrder.add(key);
        }

        List<String> payloadInsertionOrder = new ArrayList<>(taxonomyClaims);
        JWTCreator.Builder builder = JWTCreator.init()
                .withHeader(taxonomyJson)
                .withHeader(header)
                .withPayload(taxonomyJson);
        for (int i = 0; i < 10; i++) {
            String name = "c" + i;
            builder = builder.withClaim(name, "v" + i);
            payloadInsertionOrder.add(name);
        }
        String signed = builder.sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        Base64.Decoder urlDecoder = Base64.getUrlDecoder();
        String headerJson = new String(urlDecoder.decode(parts[0]), StandardCharsets.UTF_8);
        String payloadJson = new String(urlDecoder.decode(parts[1]), StandardCharsets.UTF_8);

        ObjectMapper objectMapper = new ObjectMapper();

        List<String> headerFields = new ArrayList<>();
        objectMapper.readValue(headerJson, ObjectNode.class)
                .fieldNames().forEachRemaining(headerFields::add);
        headerFields.retainAll(headerInsertionOrder);
        assertThat("Header insertion order should be preserved",
                headerFields, is(equalTo(headerInsertionOrder)));

        List<String> payloadFields = new ArrayList<>();
        objectMapper.readValue(payloadJson, ObjectNode.class)
                .fieldNames().forEachRemaining(payloadFields::add);
        payloadFields.retainAll(payloadInsertionOrder);
        assertThat("Claim insertion order should be preserved",
                payloadFields, is(equalTo(payloadInsertionOrder)));
    }
}
