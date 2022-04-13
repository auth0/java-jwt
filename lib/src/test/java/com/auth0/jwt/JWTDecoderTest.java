package com.auth0.jwt;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.hamcrest.collection.IsCollectionWithSize;
import org.hamcrest.core.IsIterableContaining;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class JWTDecoderTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void getSubject() {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ");
        assertThat(jwt.getSubject(), is(notNullValue()));
        assertThat(jwt.getSubject(), is("1234567890"));
    }

    // Exceptions
    @Test
    public void shouldThrowIfTheContentIsNotProperlyEncoded() {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage(startsWith("The string '"));
        exception.expectMessage(endsWith("' doesn't have a valid JSON format."));
        JWT.decode("eyJ0eXAiOiJKV1QiLCJhbGciO-corrupted.eyJ0ZXN0IjoxMjN9.sLtFC2rLAzN0-UJ13OLQX6ezNptAQzespaOGwCnpqk");
    }

    @Test
    public void shouldThrowIfLessThan3Parts() {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("The token was expected to have 3 parts, but got 2.");
        JWT.decode("two.parts");
    }

    @Test
    public void shouldThrowIfMoreThan3Parts() {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("The token was expected to have 3 parts, but got 4.");
        JWT.decode("this.has.four.parts");
    }

    @Test
    public void shouldThrowIfPayloadHasInvalidJSONFormat() {
        String validJson = "{}";
        String invalidJson = "}{";
        exception.expect(JWTDecodeException.class);
        exception.expectMessage(String.format("The string '%s' doesn't have a valid JSON format.", invalidJson));
        customJWT(validJson, invalidJson, "signature");
    }

    @Test
    public void shouldThrowIfHeaderHasInvalidJSONFormat() {
        String validJson = "{}";
        String invalidJson = "}{";
        exception.expect(JWTDecodeException.class);
        exception.expectMessage(String.format("The string '%s' doesn't have a valid JSON format.", invalidJson));
        customJWT(invalidJson, validJson, "signature");
    }

    @Test
    public void shouldThrowWhenHeaderNotValidBase64() {
        exception.expect(JWTDecodeException.class);
        exception.expectCause(isA(IllegalArgumentException.class));

        String jwt = "eyJhbGciOiJub25l+IiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.Ox-WRXRaGAuWt2KfPvWiGcCrPqZtbp_4OnQzZXaTfss";
        JWT.decode(jwt);
    }

    @Test
    public void shouldThrowWhenPayloadNotValidBase64() {
        exception.expect(JWTDecodeException.class);
        exception.expectCause(isA(IllegalArgumentException.class));

        String jwt = "eyJhbGciOiJub25lIiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRo+MCJ9.Ox-WRXRaGAuWt2KfPvWiGcCrPqZtbp_4OnQzZXaTfss";
        JWT.decode(jwt);
    }

    // Parts

    @Test
    public void shouldGetStringToken() {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getToken(), is(notNullValue()));
        assertThat(jwt.getToken(), is("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ"));
    }

    @Test
    public void shouldGetHeader() {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getHeader(), is("eyJhbGciOiJIUzI1NiJ9"));
    }

    @Test
    public void shouldGetPayload() {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getPayload(), is("e30"));
    }

    @Test
    public void shouldGetSignature() {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getSignature(), is("XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ"));
    }

    // Standard Claims

    @Test
    public void shouldGetIssuer() {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJKb2huIERvZSJ9.SgXosfRR_IwCgHq5lF3tlM-JHtpucWCRSaVuoHTbWbQ");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getIssuer(), is("John Doe"));
    }

    @Test
    public void shouldGetSubject() {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJUb2szbnMifQ.RudAxkslimoOY3BLl2Ghny3BrUKu9I1ZrXzCZGDJtNs");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getSubject(), is("Tok3ns"));
    }

    @Test
    public void shouldGetArrayAudience() {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsiSG9wZSIsIlRyYXZpcyIsIlNvbG9tb24iXX0.Tm4W8WnfPjlmHSmKFakdij0on2rWPETpoM7Sh0u6-S4");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getAudience(), is(IsCollectionWithSize.hasSize(3)));
        assertThat(jwt.getAudience(), is(IsIterableContaining.hasItems("Hope", "Travis", "Solomon")));
    }

    @Test
    public void shouldGetStringAudience() {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJKYWNrIFJleWVzIn0.a4I9BBhPt1OB1GW67g2P1bEHgi6zgOjGUL4LvhE9Dgc");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getAudience(), is(IsCollectionWithSize.hasSize(1)));
        assertThat(jwt.getAudience(), is(IsIterableContaining.hasItems("Jack Reyes")));
    }

    @Test
    public void shouldGetExpirationTime() {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE0NzY3MjcwODZ9.L9dcPHEDQew2u9MkDCORFkfDGcSOsgoPqNY-LUMLEHg");
        assertThat(jwt, is(notNullValue()));
        long ms = 1476727086L * 1000;
        assertThat(jwt.getExpiresAt(), is(equalTo(new Date(ms))));
        assertThat(jwt.getExpiresAtAsInstant(), is(equalTo(Instant.ofEpochMilli(ms))));
    }

    @Test
    public void shouldGetNotBefore() {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJuYmYiOjE0NzY3MjcwODZ9.tkpD3iCPQPVqjnjpDVp2bJMBAgpVCG9ZjlBuMitass0");
        assertThat(jwt, is(notNullValue()));
        long ms = 1476727086L * 1000;
        assertThat(jwt.getNotBefore(), is(equalTo(new Date(ms))));
        assertThat(jwt.getNotBeforeAsInstant(), is(equalTo(Instant.ofEpochMilli(ms))));
    }

    @Test
    public void shouldGetIssuedAt() {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NzY3MjcwODZ9.KPjGoW665E8V5_27Jugab8qSTxLk2cgquhPCBfAP0_w");
        assertThat(jwt, is(notNullValue()));
        long ms = 1476727086L * 1000;
        assertThat(jwt.getIssuedAt(), is(equalTo(new Date(ms))));
        assertThat(jwt.getIssuedAtAsInstant(), is(equalTo(Instant.ofEpochMilli(ms))));
    }

    @Test
    public void shouldGetId() {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIxMjM0NTY3ODkwIn0.m3zgEfVUFOd-CvL3xG5BuOWLzb0zMQZCqiVNQQOPOvA");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getId(), is("1234567890"));
    }

    @Test
    public void shouldGetContentType() {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiIsImN0eSI6ImF3ZXNvbWUifQ.e30.AIm-pJDOaAyct9qKMlN-lQieqNDqc3d4erqUZc5SHAs");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getContentType(), is("awesome"));
    }

    @Test
    public void shouldGetType() {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.e30.WdFmrzx8b9v_a-r6EHC2PTAaWywgm_8LiP8RBRhYwkI");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getType(), is("JWS"));
    }

    @Test
    public void shouldGetAlgorithm() {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getAlgorithm(), is("HS256"));
    }

    // Private Claims

    @Test
    public void shouldGetMissingClaimIfClaimDoesNotExist() {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.e30.K17vlwhE8FCMShdl1_65jEYqsQqBOVMPUU9IgG-QlTM");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getClaim("notExisting"), is(notNullValue()));
        assertThat(jwt.getClaim("notExisting").isMissing(), is(true));
        assertThat(jwt.getClaim("notExisting").isNull(), is(false));
    }

    @Test
    public void shouldGetValidClaim() {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJvYmplY3QiOnsibmFtZSI6ImpvaG4ifX0.lrU1gZlOdlmTTeZwq0VI-pZx2iV46UWYd5-lCjy6-c4");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getClaim("object"), is(notNullValue()));
        assertThat(jwt.getClaim("object"), is(instanceOf(Claim.class)));
    }

    @Test
    public void shouldNotGetNullClaimIfClaimIsEmptyObject() {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.eyJvYmplY3QiOnt9fQ.d3nUeeL_69QsrHL0ZWij612LHEQxD8EZg1rNoY3a4aI");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getClaim("object"), is(notNullValue()));
        assertThat(jwt.getClaim("object").isNull(), is(false));
    }

    @Test
    public void shouldGetCustomClaimOfTypeInteger() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoxMjN9.XZAudnA7h3_Al5kJydzLjw6RzZC3Q6OvnLEYlhNW7HA";
        DecodedJWT jwt = JWT.decode(token);
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getClaim("name").asInt(), is(123));
    }

    @Test
    public void shouldGetCustomClaimOfTypeDouble() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoyMy40NX0.7pyX2OmEGaU9q15T8bGFqRm-d3RVTYnqmZNZtxMKSlA";
        DecodedJWT jwt = JWT.decode(token);
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getClaim("name").asDouble(), is(23.45));
    }

    @Test
    public void shouldGetCustomClaimOfTypeBoolean() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjp0cnVlfQ.FwQ8VfsZNRqBa9PXMinSIQplfLU4-rkCLfIlTLg_MV0";
        DecodedJWT jwt = JWT.decode(token);
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getClaim("name").asBoolean(), is(true));
    }

    @Test
    public void shouldGetCustomClaimOfTypeDate() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoxNDc4ODkxNTIxfQ.mhioumeok8fghQEhTKF3QtQAksSvZ_9wIhJmgZLhJ6c";
        Date date = new Date(1478891521000L);
        DecodedJWT jwt = JWT.decode(token);
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getClaim("name").asDate().getTime(), is(date.getTime()));
    }

    @Test
    public void shouldGetCustomClaimOfTypeInstant() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoxNDc4ODkxNTIxfQ.mhioumeok8fghQEhTKF3QtQAksSvZ_9wIhJmgZLhJ6c";
        Instant instant = Instant.ofEpochSecond(1478891521L);
        DecodedJWT jwt = JWT.decode(token);
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getClaim("name").asInstant(), is(equalTo(instant)));
    }

    @Test
    public void shouldGetCustomArrayClaimOfTypeString() {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbInRleHQiLCIxMjMiLCJ0cnVlIl19.lxM8EcmK1uSZRAPd0HUhXGZJdauRmZmLjoeqz4J9yAA";
        DecodedJWT jwt = JWT.decode(token);
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getClaim("name").asArray(String.class), arrayContaining("text", "123", "true"));
    }

    @Test
    public void shouldGetCustomArrayClaimOfTypeInteger() {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbMSwyLDNdfQ.UEuMKRQYrzKAiPpPLhIVawWkKWA1zj0_GderrWUIyFE";
        DecodedJWT jwt = JWT.decode(token);
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getClaim("name").asArray(Integer.class), arrayContaining(1, 2, 3));
    }

    @Test
    public void shouldGetCustomMapClaim() {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjp7InN0cmluZyI6InZhbHVlIiwibnVtYmVyIjoxLCJib29sZWFuIjp0cnVlLCJlbXB0eSI6bnVsbH19.6xkCuYZnu4RA0xZSxlYSYAqzy9JDWsDtIWqSCUZlPt8";
        DecodedJWT jwt = JWT.decode(token);
        assertThat(jwt, is(notNullValue()));
        Map<String, Object> map = jwt.getClaim("name").asMap();
        assertThat(map, hasEntry("string", "value"));
        assertThat(map, hasEntry("number", 1));
        assertThat(map, hasEntry("boolean", true));
        assertThat(map, hasEntry("empty", null));
    }

    @Test
    public void shouldGetCustomNullClaim() {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpudWxsfQ.X4ALHe7uYqEcXWFBnwBUNRKwmwrtDEGZ2aynRYYUx8c";
        DecodedJWT jwt = JWT.decode(token);
        assertThat(jwt.getClaim("name").isNull(), is(true));
    }

    @Test
    public void shouldGetListClaim() {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbbnVsbCwiaGVsbG8iXX0.SpcuQRBGdTV0ofHdxBSnhWEUsQi89noZUXin2Thwb70";
        DecodedJWT jwt = JWT.decode(token);
        assertThat(jwt.getClaim("name").asList(String.class), contains(null, "hello"));
    }

    @Test
    public void shouldGetAvailableClaims() {
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
    public void shouldSerializeAndDeserialize() throws Exception {
        DecodedJWT originalJwt = JWT.decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEyMzQ1Njc4OTAsImlhdCI6MTIzNDU2Nzg5MCwibmJmIjoxMjM0NTY3ODkwLCJqdGkiOiJodHRwczovL2p3dC5pby8iLCJhdWQiOiJodHRwczovL2RvbWFpbi5hdXRoMC5jb20iLCJzdWIiOiJsb2dpbiIsImlzcyI6ImF1dGgwIiwiZXh0cmFDbGFpbSI6IkpvaG4gRG9lIn0.2_0nxDPJwOk64U5V5V9pt8U92jTPJbGsHYQ35HYhbdE");

        assertThat(originalJwt, is(instanceOf(Serializable.class)));

        byte[] serialized = serialize(originalJwt);
        DecodedJWT deserializedJwt = (DecodedJWT) deserialize(serialized);

        assertThat(originalJwt.getHeader(), is(equalTo(deserializedJwt.getHeader())));
        assertThat(originalJwt.getPayload(), is(equalTo(deserializedJwt.getPayload())));
        assertThat(originalJwt.getSignature(), is(equalTo(deserializedJwt.getSignature())));
        assertThat(originalJwt.getToken(), is(equalTo(deserializedJwt.getToken())));
        assertThat(originalJwt.getAlgorithm(), is(equalTo(deserializedJwt.getAlgorithm())));
        assertThat(originalJwt.getAudience(), is(equalTo(deserializedJwt.getAudience())));
        assertThat(originalJwt.getContentType(), is(equalTo(deserializedJwt.getContentType())));
        assertThat(originalJwt.getExpiresAt(), is(equalTo(deserializedJwt.getExpiresAt())));
        assertThat(originalJwt.getId(), is(equalTo(deserializedJwt.getId())));
        assertThat(originalJwt.getIssuedAt(), is(equalTo(deserializedJwt.getIssuedAt())));
        assertThat(originalJwt.getIssuer(), is(equalTo(deserializedJwt.getIssuer())));
        assertThat(originalJwt.getKeyId(), is(equalTo(deserializedJwt.getKeyId())));
        assertThat(originalJwt.getNotBefore(), is(equalTo(deserializedJwt.getNotBefore())));
        assertThat(originalJwt.getSubject(), is(equalTo(deserializedJwt.getSubject())));
        assertThat(originalJwt.getType(), is(equalTo(deserializedJwt.getType())));
        assertThat(originalJwt.getClaims().get("extraClaim").asString(),
                is(equalTo(deserializedJwt.getClaims().get("extraClaim").asString())));
    }

    @Test
    public void shouldDecodeHeaderClaims() {
        String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImRhdGUiOjE2NDczNTgzMjUsInN0cmluZyI6InN0cmluZyIsImJvb2wiOnRydWUsImRvdWJsZSI6MTIzLjEyMywibGlzdCI6WzE2NDczNTgzMjVdLCJtYXAiOnsiZGF0ZSI6MTY0NzM1ODMyNSwiaW5zdGFudCI6MTY0NzM1ODMyNX0sImludCI6NDIsImxvbmciOjQyMDAwMDAwMDAsImluc3RhbnQiOjE2NDczNTgzMjV9.eyJpYXQiOjE2NDczNjA4ODF9.S2nZDM03ZDvLMeJLWOIqWZ9kmYHZUueyQiIZCCjYNL8";

        Instant expectedInstant = Instant.ofEpochSecond(1647358325);
        Date expectedDate = Date.from(expectedInstant);

        DecodedJWT decoded = JWT.decode(jwt);
        assertThat(decoded, is(notNullValue()));
        assertThat(decoded.getHeaderClaim("date").asDate(), is(expectedDate));
        assertThat(decoded.getHeaderClaim("instant").asInstant(), is(expectedInstant));
        assertThat(decoded.getHeaderClaim("string").asString(), is("string"));
        assertThat(decoded.getHeaderClaim("bool").asBoolean(), is(true));
        assertThat(decoded.getHeaderClaim("double").asDouble(), is(123.123));
        assertThat(decoded.getHeaderClaim("int").asInt(), is(42));
        assertThat(decoded.getHeaderClaim("long").asLong(), is(4200000000L));

        Map<String, Object> headerMap = decoded.getHeaderClaim("map").asMap();
        assertThat(headerMap, is(notNullValue()));
        assertThat(headerMap.size(), is(2));
        assertThat(headerMap, hasEntry("date", 1647358325));
        assertThat(headerMap, hasEntry("instant", 1647358325));

        List<Object> headerList = decoded.getHeaderClaim("list").asList(Object.class);
        assertThat(headerList, is(notNullValue()));
        assertThat(headerList.size(), is(1));
        assertThat(headerList, contains(1647358325));
    }

    //Helper Methods

    private DecodedJWT customJWT(String jsonHeader, String jsonPayload, String signature) {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(jsonHeader.getBytes(StandardCharsets.UTF_8));
        String body = Base64.getUrlEncoder().withoutPadding().encodeToString(jsonPayload.getBytes(StandardCharsets.UTF_8));
        return JWT.decode(String.format("%s.%s.%s", header, body, signature));
    }

    private static byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        ObjectOutputStream o = new ObjectOutputStream(b);
        o.writeObject(obj);
        return b.toByteArray();
    }

    private static Object deserialize(byte[] bytes) throws IOException, ClassNotFoundException {
        ByteArrayInputStream b = new ByteArrayInputStream(bytes);
        ObjectInputStream o = new ObjectInputStream(b);
        return o.readObject();
    }

}