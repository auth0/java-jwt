package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.ECDSAKeyProvider;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.apache.commons.codec.binary.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

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
    public void shouldAddKeyIdIfAvailableFromRSAAlgorithms() throws Exception {
        RSAPrivateKey privateKey = (RSAPrivateKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_RSA, "RSA");
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        when(provider.getPrivateKeyId()).thenReturn("my-key-id");
        when(provider.getPrivateKey()).thenReturn(privateKey);

        String signed = JWTCreator.init()
                .sign(Algorithm.RSA256(provider));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
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
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
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
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
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
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("kid", "my-key-id"));
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
    public void shouldAcceptCustomClaimOfTypeLong() throws Exception {
        String jwt = JWTCreator.init()
                .withClaim("name", Long.MAX_VALUE)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjo5MjIzMzcyMDM2ODU0Nzc1ODA3fQ"));
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

    @Test
    public void shouldAcceptCustomArrayClaimOfTypeLong() throws Exception {
        String jwt = JWTCreator.init()
                .withArrayClaim("name", new Long[]{1L, 2L, 3L})
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjpbMSwyLDNdfQ"));
    }

    @Test
    public void shouldAcceptCustomCollectionClaimOfBooleanType() throws Exception {
        Collection<Object> collection = new ArrayList<>();
        collection.add(true);
        collection.add(false);

        String jwt = JWTCreator.init().withClaim("name", collection).sign(Algorithm.HMAC256("secret"));
        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjpbdHJ1ZSxmYWxzZV19"));
    }

    @Test
    public void shouldAcceptCustomCollectionClaimOfIntegerType() throws Exception {
        Collection<Object> collection = new ArrayList<>();
        collection.add(1);
        collection.add(2);

        String jwt = JWTCreator.init().withClaim("name", collection).sign(Algorithm.HMAC256("secret"));
        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjpbMSwyXX0"));
    }

    @Test
    public void shouldAcceptCustomCollectionClaimOfLongType() throws Exception {
        Collection<Object> collection = new ArrayList<>();
        collection.add(1L);
        collection.add(2L);

        String jwt = JWTCreator.init().withClaim("name", collection).sign(Algorithm.HMAC256("secret"));
        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjpbMSwyXX0"));
    }

    @Test
    public void shouldAcceptCustomCollectionClaimOfStringType() throws Exception {
        Collection<Object> collection = new ArrayList<>();
        collection.add("1");
        collection.add("2");

        String jwt = JWTCreator.init().withClaim("name", collection).sign(Algorithm.HMAC256("secret"));
        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjpbIjEiLCIyIl19"));
    }

    @Test
    public void shouldAcceptCustomCollectionClaimOfDoubleType() throws Exception {
        Collection<Object> collection = new ArrayList<>();
        collection.add(1.2);
        collection.add(3.4);

        String jwt = JWTCreator.init().withClaim("name", collection).sign(Algorithm.HMAC256("secret"));
        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjpbMS4yLDMuNF19"));
    }

    @Test
    public void shouldAcceptCustomCollectionClaimOfDateType() throws Exception {
        Collection<Object> collection = new ArrayList<>();
        collection.add(new Date(123456));
        collection.add(new Date(7890123));

        String jwt = JWTCreator.init().withClaim("name", collection).sign(Algorithm.HMAC256("secret"));
        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjpbMTIzNDU2LDc4OTAxMjNdfQ"));
    }

    @Test
    public void shouldAcceptCustomCollectionClaimOfIntegerArrayType() throws Exception {
        Collection<Object> collection = new ArrayList<>();
        collection.add(new Integer[] { 1, 2 });

        String jwt = JWTCreator.init().withClaim("name", collection).sign(Algorithm.HMAC256("secret"));
        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjpbWzEsMl1dfQ"));
    }

    @Test
    public void shouldAcceptCustomCollectionClaimOfLongArrayType() throws Exception {
        Collection<Object> collection = new ArrayList<>();
        collection.add(new Long[] { 3L, 4L });

        String jwt = JWTCreator.init().withClaim("name", collection).sign(Algorithm.HMAC256("secret"));
        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjpbWzMsNF1dfQ"));
    }

    @Test
    public void shouldAcceptCustomCollectionClaimOfStringArrayType() throws Exception {
        Collection<Object> collection = new ArrayList<>();
        collection.add(new String[] { "5", "6" });

        String jwt = JWTCreator.init().withClaim("name", collection).sign(Algorithm.HMAC256("secret"));
        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjpbWyI1IiwiNiJdXX0"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAcceptCustomCollectionClaimOfUnSupportedType() throws Exception {
        Collection<Object> collection = new ArrayList<>();
        collection.add(new JWTTest());

        JWTCreator.init().withClaim("name", collection);
    }

    @Test
    public void shouldAcceptCustomCollectionClaimOfArrayType() throws Exception {
        Collection<Object> collection = new ArrayList<>();
        collection.add(new Integer[] { 1, 2, 3 });
        collection.add(new Long[] { 1L, 2L, 3L });
        collection.add(new String[] { "1", "2", "3" });

        String jwt = JWTCreator.init().withClaim("name", collection).sign(Algorithm.HMAC256("secret"));
        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjpbWzEsMiwzXSxbMSwyLDNdLFsiMSIsIjIiLCIzIl1dfQ"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAcceptCustomCollectionClaimOfUnSupportedArrayType() throws Exception {
        Collection<Object> collection = new ArrayList<>();
        collection.add(new Boolean[] { true });

        JWTCreator.init().withClaim("name", collection);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAcceptNullCustomCollectionClaim() throws Exception {
        Collection<Object> collection = null;
        JWTCreator.init().withClaim("name", collection);
    }

    @Test
    public void shouldAcceptEmptyCustomCollectionClaim() throws Exception {
        Collection<Object> collection = new ArrayList<>();
        JWTCreator.init().withClaim("name", collection);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAcceptNullCustomMapClaim() throws Exception {
        Map<String, Object> map = null;
        JWTCreator.init().withClaim("name", map);
    }

    @Test
    public void shouldAcceptEmptyCustomMapClaim() throws Exception {
        Map<String, Object> map = new HashMap<>();
        JWTCreator.init().withClaim("name", map);
    }

    @Test
    public void shouldAcceptCustomMapClaimOfTypeLong() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("first", 1L);
        map.put("two", Long.MAX_VALUE);
        map.put("three", null);

        String jwt = JWTCreator.init().withClaim("name", map).sign(Algorithm.HMAC256("secret"));
        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjp7InR3byI6OTIyMzM3MjAzNjg1NDc3NTgwNywidGhyZWUiOm51bGwsImZpcnN0IjoxfX0"));
    }

    @Test
    public void shouldAcceptCustomMapClaimOfTypeInteger() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("first", 1);
        map.put("two", Integer.MAX_VALUE);
        map.put("three", null);

        String jwt = JWTCreator.init().withClaim("name", map).sign(Algorithm.HMAC256("secret"));
        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjp7InR3byI6MjE0NzQ4MzY0NywidGhyZWUiOm51bGwsImZpcnN0IjoxfX0"));
    }

    @Test
    public void shouldAcceptCustomMapClaimOfTypeDouble() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("first", 12.34);
        map.put("two", Double.MAX_VALUE);
        map.put("three", null);

        String jwt = JWTCreator.init().withClaim("name", map).sign(Algorithm.HMAC256("secret"));
        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1],
                is("eyJuYW1lIjp7InR3byI6MS43OTc2OTMxMzQ4NjIzMTU3RTMwOCwidGhyZWUiOm51bGwsImZpcnN0IjoxMi4zNH19"));
    }

    @Test
    public void shouldAcceptCustomMapClaimOfTypeString() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("first", "test");
        map.put("two", "name");
        map.put("three", null);

        String jwt = JWTCreator.init().withClaim("name", map).sign(Algorithm.HMAC256("secret"));
        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjp7InR3byI6Im5hbWUiLCJ0aHJlZSI6bnVsbCwiZmlyc3QiOiJ0ZXN0In19"));
    }

    @Test
    public void shouldAcceptCustomMapClaimOfTypeDate() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("first", new Date(1478891521000L));
        map.put("two", null);

        String jwt = JWTCreator.init().withClaim("name", map).sign(Algorithm.HMAC256("secret"));
        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjp7InR3byI6bnVsbCwiZmlyc3QiOjE0Nzg4OTE1MjEwMDB9fQ"));
    }

    @Test
    public void shouldAcceptCustomMapClaimOfTypeBoolean() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("first", true);
        map.put("two", false);
        map.put("three", null);

        String jwt = JWTCreator.init().withClaim("name", map).sign(Algorithm.HMAC256("secret"));
        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjp7InR3byI6ZmFsc2UsInRocmVlIjpudWxsLCJmaXJzdCI6dHJ1ZX19"));
    }

    @Test
    public void shouldAcceptCustomMapClaimOfArrayType() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("first", new Integer[] { 1, 2, 3 });
        map.put("two", new Long[] { 4L, 5L, 6L });
        map.put("three", new String[] { "1", "2", "3" });

        String jwt = JWTCreator.init().withClaim("name", map).sign(Algorithm.HMAC256("secret"));
        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjp7InR3byI6WzQsNSw2XSwidGhyZWUiOlsiMSIsIjIiLCIzIl0sImZpcnN0IjpbMSwyLDNdfX0"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAcceptCustomMapClaimOfTypeCollection() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("first", Arrays.asList(new Integer[] { 1, 2, 3 }));
        map.put("two", new Integer[] { 2, 3, 4 });

        JWTCreator.init().withClaim("name", map);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAcceptWhenNonSerializedCustomClassIsUsed() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("first", new JWTCreatorTest());

        JWTCreator.init().withClaim("name", map);
    }
}