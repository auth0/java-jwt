package com.auth0.jwt;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.impl.NullClaim;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.codec.binary.Base64;
import org.hamcrest.collection.IsCollectionWithSize;
import org.hamcrest.core.IsCollectionContaining;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

@SuppressWarnings("unchecked")
public class JWTDecoderTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void getSubject() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ");
        assertThat(jwt.getSubject(), is(notNullValue()));
        assertThat(jwt.getSubject(), is("1234567890"));
    }

    // Exceptions
    @Test
    public void shouldThrowIfLessThan3Parts() throws Exception {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("The token was expected to have 3 parts, but got 2.");
        JWT.decode("two.parts");
    }

    @Test
    public void shouldThrowIfMoreThan3Parts() throws Exception {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("The token was expected to have 3 parts, but got 4.");
        JWT.decode("this.has.four.parts");
    }

    @Test
    public void shouldThrowIfPayloadHasInvalidJSONFormat() throws Exception {
        String validJson = "{}";
        String invalidJson = "}{";
        exception.expect(JWTDecodeException.class);
        exception.expectMessage(String.format("The string '%s' doesn't have a valid JSON format.", invalidJson));
        customJWT(validJson, invalidJson, "signature");
    }

    @Test
    public void shouldThrowIfHeaderHasInvalidJSONFormat() throws Exception {
        String validJson = "{}";
        String invalidJson = "}{";
        exception.expect(JWTDecodeException.class);
        exception.expectMessage(String.format("The string '%s' doesn't have a valid JSON format.", invalidJson));
        customJWT(invalidJson, validJson, "signature");
    }

    // Parts

    @Test
    public void shouldGetStringToken() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getToken(), is(notNullValue()));
        assertThat(jwt.getToken(), is("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ"));
    }

    @Test
    public void shouldGetHeader() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getHeader(), is("eyJhbGciOiJIUzI1NiJ9"));
    }

    @Test
    public void shouldGetPayload() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getPayload(), is("e30"));
    }

    @Test
    public void shouldGetSignature() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getSignature(), is("XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ"));
    }

    // Public PublicClaims

    @Test
    public void shouldGetIssuer() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJKb2huIERvZSJ9.SgXosfRR_IwCgHq5lF3tlM-JHtpucWCRSaVuoHTbWbQ");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getIssuer(), is("John Doe"));
    }

    @Test
    public void shouldGetSubject() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJUb2szbnMifQ.RudAxkslimoOY3BLl2Ghny3BrUKu9I1ZrXzCZGDJtNs");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getSubject(), is("Tok3ns"));
    }

    @Test
    public void shouldGetArrayAudience() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsiSG9wZSIsIlRyYXZpcyIsIlNvbG9tb24iXX0.Tm4W8WnfPjlmHSmKFakdij0on2rWPETpoM7Sh0u6-S4");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getAudience(), is(IsCollectionWithSize.hasSize(3)));
        assertThat(jwt.getAudience(), is(IsCollectionContaining.hasItems("Hope", "Travis", "Solomon")));
    }

    @Test
    public void shouldGetStringAudience() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJKYWNrIFJleWVzIn0.a4I9BBhPt1OB1GW67g2P1bEHgi6zgOjGUL4LvhE9Dgc");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getAudience(), is(IsCollectionWithSize.hasSize(1)));
        assertThat(jwt.getAudience(), is(IsCollectionContaining.hasItems("Jack Reyes")));
    }

    @Test
    public void shouldGetExpirationTime() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE0NzY3MjcwODZ9.L9dcPHEDQew2u9MkDCORFkfDGcSOsgoPqNY-LUMLEHg");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getExpiresAt(), is(instanceOf(Date.class)));
        long ms = 1476727086L * 1000;
        Date expectedDate = new Date(ms);
        assertThat(jwt.getExpiresAt(), is(notNullValue()));
        assertThat(jwt.getExpiresAt(), is(equalTo(expectedDate)));
    }

    @Test
    public void shouldGetNotBefore() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJuYmYiOjE0NzY3MjcwODZ9.tkpD3iCPQPVqjnjpDVp2bJMBAgpVCG9ZjlBuMitass0");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getNotBefore(), is(instanceOf(Date.class)));
        long ms = 1476727086L * 1000;
        Date expectedDate = new Date(ms);
        assertThat(jwt.getNotBefore(), is(notNullValue()));
        assertThat(jwt.getNotBefore(), is(equalTo(expectedDate)));
    }

    @Test
    public void shouldGetIssuedAt() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NzY3MjcwODZ9.KPjGoW665E8V5_27Jugab8qSTxLk2cgquhPCBfAP0_w");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getIssuedAt(), is(instanceOf(Date.class)));
        long ms = 1476727086L * 1000;
        Date expectedDate = new Date(ms);
        assertThat(jwt.getIssuedAt(), is(notNullValue()));
        assertThat(jwt.getIssuedAt(), is(equalTo(expectedDate)));
    }

    @Test
    public void shouldGetId() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIxMjM0NTY3ODkwIn0.m3zgEfVUFOd-CvL3xG5BuOWLzb0zMQZCqiVNQQOPOvA");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getId(), is("1234567890"));
    }

    @Test
    public void shouldGetContentType() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiIsImN0eSI6ImF3ZXNvbWUifQ.e30.AIm-pJDOaAyct9qKMlN-lQieqNDqc3d4erqUZc5SHAs");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getContentType(), is("awesome"));
    }

    @Test
    public void shouldGetType() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.e30.WdFmrzx8b9v_a-r6EHC2PTAaWywgm_8LiP8RBRhYwkI");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getType(), is("JWS"));
    }

    @Test
    public void shouldGetAlgorithm() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getAlgorithm(), is("HS256"));
    }

    //Private PublicClaims

    @Test
    public void shouldGetMissingClaimIfClaimDoesNotExist() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.e30.K17vlwhE8FCMShdl1_65jEYqsQqBOVMPUU9IgG-QlTM");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getClaim("notExisting"), is(notNullValue()));
        assertThat(jwt.getClaim("notExisting"), is(instanceOf(NullClaim.class)));
    }

    @Test
    public void shouldGetValidClaim() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJvYmplY3QiOnsibmFtZSI6ImpvaG4ifX0.lrU1gZlOdlmTTeZwq0VI-pZx2iV46UWYd5-lCjy6-c4");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getClaim("object"), is(notNullValue()));
        assertThat(jwt.getClaim("object"), is(instanceOf(Claim.class)));
    }

    @Test
    public void shouldNotGetNullClaimIfClaimIsEmptyObject() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJvYmplY3QiOnt9fQ.d3nUeeL_69QsrHL0ZWij612LHEQxD8EZg1rNoY3a4aI");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getClaim("object"), is(notNullValue()));
        assertThat(jwt.getClaim("object").isNull(), is(false));
    }

    @Test
    public void shouldGetCustomClaimOfTypeInteger() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoxMjN9.XZAudnA7h3_Al5kJydzLjw6RzZC3Q6OvnLEYlhNW7HA";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Assert.assertThat(jwt.getClaim("name").asInt(), is(123));
    }

    @Test
    public void shouldGetCustomClaimOfTypeDouble() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoyMy40NX0.7pyX2OmEGaU9q15T8bGFqRm-d3RVTYnqmZNZtxMKSlA";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Assert.assertThat(jwt.getClaim("name").asDouble(), is(23.45));
    }

    @Test
    public void shouldGetCustomClaimOfTypeBoolean() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjp0cnVlfQ.FwQ8VfsZNRqBa9PXMinSIQplfLU4-rkCLfIlTLg_MV0";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Assert.assertThat(jwt.getClaim("name").asBoolean(), is(true));
    }

    @Test
    public void shouldGetCustomClaimOfTypeDate() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoxNDc4ODkxNTIxfQ.mhioumeok8fghQEhTKF3QtQAksSvZ_9wIhJmgZLhJ6c";
        Date date = new Date(1478891521000L);
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Assert.assertThat(jwt.getClaim("name").asDate().getTime(), is(date.getTime()));
    }

    @Test
    public void shouldGetCustomArrayClaimOfTypeString() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbInRleHQiLCIxMjMiLCJ0cnVlIl19.lxM8EcmK1uSZRAPd0HUhXGZJdauRmZmLjoeqz4J9yAA";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Assert.assertThat(jwt.getClaim("name").asArray(String.class), arrayContaining("text", "123", "true"));
    }

    @Test
    public void shouldGetCustomArrayClaimOfTypeInteger() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbMSwyLDNdfQ.UEuMKRQYrzKAiPpPLhIVawWkKWA1zj0_GderrWUIyFE";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Assert.assertThat(jwt.getClaim("name").asArray(Integer.class), arrayContaining(1, 2, 3));
    }

    @Test
    public void shouldGetCustomMapClaim() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjp7InN0cmluZyI6InZhbHVlIiwibnVtYmVyIjoxLCJib29sZWFuIjp0cnVlfX0.-8aIaXd2-rp1lLuDEQmCeisCBX9X_zbqdPn2llGxNoc";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Map<String, Object> map = jwt.getClaim("name").asMap();
        Assert.assertThat(map, hasEntry("string", (Object) "value"));
        Assert.assertThat(map, hasEntry("number", (Object) 1));
        Assert.assertThat(map, hasEntry("boolean", (Object) true));
    }

    @Test
    public void shouldGetAvailableClaims() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEyMzQ1Njc4OTAsImlhdCI6MTIzNDU2Nzg5MCwibmJmIjoxMjM0NTY3ODkwLCJqdGkiOiJodHRwczovL2p3dC5pby8iLCJhdWQiOiJodHRwczovL2RvbWFpbi5hdXRoMC5jb20iLCJzdWIiOiJsb2dpbiIsImlzcyI6ImF1dGgwIiwiZXh0cmFDbGFpbSI6IkpvaG4gRG9lIn0.2_0nxDPJwOk64U5V5V9pt8U92jTPJbGsHYQ35HYhbdE");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getClaims(), is(notNullValue()));
        assertThat(jwt.getClaims(), is(instanceOf(Map.class)));
        assertThat(jwt.getClaims().get("exp"), is(notNullValue()));
        assertThat(jwt.getClaims().get("iat"), is(notNullValue()));
        assertThat(jwt.getClaims().get("nbf"), is(notNullValue()));
        assertThat(jwt.getClaims().get("jti"), is(notNullValue()));
        assertThat(jwt.getClaims().get("aud"), is(notNullValue()));
        assertThat(jwt.getClaims().get("sub"), is(notNullValue()));
        assertThat(jwt.getClaims().get("iss"), is(notNullValue()));
        assertThat(jwt.getClaims().get("extraClaim"), is(notNullValue()));
    }

    @Test
    public void shouldGetMapOfListIntegerClaimValue() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjp7InR3byI6WzIsMyw0XSwiZmlyc3QiOlsxLDIsM119fQ.25extEOljDo2RDMGI1C9s8dy-0OYcSbf__rCX-7O8ig";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Map<String, Object> map = jwt.getClaim("name").asMap();
        Assert.assertThat((List<Integer>) map.get("first"), contains(1, 2, 3));
        Assert.assertThat((List<Integer>) map.get("two"), contains(2, 3, 4));
    }

    @Test
    public void shouldGetMapOfBooleanClaimValue() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjp7InR3byI6ZmFsc2UsInRocmVlIjpudWxsLCJmaXJzdCI6dHJ1ZX19.1tXW692Iq-7OVj1248_vKCvpoR6K_6dHcfH-K9OWg7s";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Map<String, Object> map = jwt.getClaim("name").asMap();
        Assert.assertTrue((Boolean) map.get("first"));
        Assert.assertFalse((Boolean) map.get("two"));
    }

    @Test
    public void shouldGetMapOfDateClaimValue() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjp7InR3byI6bnVsbCwiZmlyc3QiOjE0Nzg4OTE1MjEwMDB9fQ.xckuzg5t5zheqoWhQD5hStMmYE1pgbtv7fDj_v-shqw";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Map<String, Object> map = jwt.getClaim("name").asMap();
        Date date = new Date(1478891521000L);
        Assert.assertThat(map.get("first"), is(date.getTime()));
    }

    @Test
    public void shouldGetMapOfStringClaimValue() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjp7InR3byI6Im5hbWUiLCJ0aHJlZSI6bnVsbCwiZmlyc3QiOiJ0ZXN0In19.vfTKLWeuC3yOeh6olaBjcj4bPoVo9huW-NERdak1A5Q";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Map<String, Object> map = jwt.getClaim("name").asMap();
        Assert.assertThat(map.get("first"), is("test"));
        Assert.assertThat(map.get("two"), is("name"));
    }

    @Test
    public void shouldGetMapOfDoubleClaimValue() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjp7InR3byI6MS43OTc2OTMxMzQ4NjIzMTU3RTMwOCwidGhyZWUiOm51bGwsImZpcnN0IjoxMi4zNH19.Q7xT-5kca5tB9VrmyLU7P9-Ezjt1TEEFGrZnd46u3A4";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Map<String, Object> map = jwt.getClaim("name").asMap();
        Assert.assertThat(map.get("first"), is(12.34));
        Assert.assertThat(map.get("two"), is(Double.MAX_VALUE));
    }

    @Test
    public void shouldGetMapOfIntegerClaimValue() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjp7InR3byI6MjE0NzQ4MzY0NywidGhyZWUiOm51bGwsImZpcnN0IjoxfX0.9a6g-D1nYSDeDb9vW6cLYW4tUgHh4S2JE07E26pcMeE";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Map<String, Object> map = jwt.getClaim("name").asMap();
        Assert.assertThat(map.get("first"), is(1));
        Assert.assertThat(map.get("two"), is(Integer.MAX_VALUE));
    }

    @Test
    public void shouldGetMapOfLongClaimValue() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjp7InR3byI6OTIyMzM3MjAzNjg1NDc3NTgwNywidGhyZWUiOm51bGwsImZpcnN0IjoxfX0.SWbYSAdyczKPQS_lMSNThNZDINd7MXygnpEKnGD6e9I";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Map<String, Object> map = jwt.getClaim("name").asMap();
        Assert.assertThat(map.get("first"), is(1));
        Assert.assertThat(map.get("two"), is(Long.MAX_VALUE));
    }

    @Test
    public void shouldGetCustomCollectionClaimOfBooleanType() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbdHJ1ZSxmYWxzZV19.qhhvteWitJkKbLWBvIyVTSEPQyg0zYxvdbqAG_BxPwE";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Collection<Object> collection = jwt.getClaim("name").as(ArrayList.class);
        Assert.assertThat(collection, contains(true, false));
    }

    @Test
    public void shouldGetCustomCollectionClaimOfIntegerType() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbMSwyXX0.7UnsF12puwoNHdzSbGkKqtx_KEW33kqWZxBHlIT8vFA";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Collection<Object> collection = jwt.getClaim("name").as(ArrayList.class);
        Assert.assertThat(collection, contains(1, 2));
    }

    @Test
    public void shouldGetCustomCollectionClaimOfLongType() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbMSwyXX0.7UnsF12puwoNHdzSbGkKqtx_KEW33kqWZxBHlIT8vFA";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Collection<Object> collection = jwt.getClaim("name").as(ArrayList.class);
        Assert.assertThat(collection, contains(1, 2));
    }

    @Test
    public void shouldGetCustomCollectionClaimOfStringType() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbIjEiLCIyIl19.bLhvAR2OqHu9IAKG0ABgY63noD9ItlBWWJ3ZNjby8BI";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Collection<Object> collection = jwt.getClaim("name").as(ArrayList.class);
        Assert.assertThat(collection, contains("1", "2"));
    }

    @Test
    public void shouldGetCustomCollectionClaimOfDoubleType() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbMS4yLDMuNF19.pxiRelpYpibcJY-rFisSTbfr-QiIEVS5hTmDXlLdTsM";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Collection<Object> collection = jwt.getClaim("name").as(ArrayList.class);
        Assert.assertThat(collection, contains(1.2, 3.4));
    }

    @Test
    public void shouldGetCustomCollectionClaimOfDateType() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbMTIzNDU2LDc4OTAxMjNdfQ.pqp27qUJQkM5QwZyMCyHxJOEQ47kZisrquLlHIc2SYg";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Collection<Long> collection = jwt.getClaim("name").asList(Long.class);
        Date date1 = new Date(123456L);
        Date date2 = new Date(7890123L);

        Assert.assertTrue(collection.containsAll(Arrays.asList(date1.getTime(), date2.getTime())));
    }

    @Test
    public void shouldGetCustomCollectionClaimOfIntegerArrayType() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbWzEsMl1dfQ.ZYBv7vFg71YsD1Sq_QWcvEABUTYfMvba7fl1pO3TaS8";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        List<Object> collection = jwt.getClaim("name").asList(Object.class);
        List<Object> expected = (ArrayList<Object>) collection.get(0);

        Assert.assertTrue(expected.containsAll(Arrays.asList(1, 2)));
    }

    @Test
    public void shouldGetCustomCollectionClaimOfLongArrayType() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbWzMsNF1dfQ.eN4lyqCSFT9TbpC7j6x4ZsLUPYAUOHGvoRHahjjpvJE";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        List<Object> collection = jwt.getClaim("name").asList(Object.class);
        List<Object> expected = (ArrayList<Object>) collection.get(0);

        Assert.assertTrue(expected.containsAll(Arrays.asList(3, 4)));
    }

    @Test
    public void shouldGetCustomCollectionClaimOfStringArrayType() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbWyI1IiwiNiJdXX0.5XhPlStgVHMhnqYuJ2WWnbZclTMXJbU1Npy1A5tWkT4";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        List<Object> collection = jwt.getClaim("name").asList(Object.class);
        List<Object> expected = (ArrayList<Object>) collection.get(0);

        Assert.assertTrue(expected.containsAll(Arrays.asList("5", "6")));
    }

    @Test
    public void shouldGetMapOfArrayClaimValue() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjp7InR3byI6WzQsNSw2XSwidGhyZWUiOlsiMSIsIjIiLCIzIl0sImZpcnN0IjpbMSwyLDNdfX0.mhQ6n5tgcjAsNfpn8Ye8Bxq4EmP4CIYy2SYrHiCa-UU";
        DecodedJWT jwt = JWT.decode(token);
        Assert.assertThat(jwt, is(notNullValue()));
        Map<String, Object> map = jwt.getClaim("name").asMap();
        Assert.assertThat((List<Integer>) map.get("first"), contains(1, 2, 3));
        Assert.assertThat((List<Long>) map.get("two"), contains(4, 5, 6));
        Assert.assertThat((List<String>) map.get("three"), contains("1", "2", "3"));
    }

    private DecodedJWT customJWT(String jsonHeader, String jsonPayload, String signature) {
        String header = Base64.encodeBase64URLSafeString(jsonHeader.getBytes(StandardCharsets.UTF_8));
        String body = Base64.encodeBase64URLSafeString(jsonPayload.getBytes(StandardCharsets.UTF_8));
        return JWT.decode(String.format("%s.%s.%s", header, body, signature));
    }

}