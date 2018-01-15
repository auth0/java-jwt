package com.auth0.jwt;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContaining;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import java.nio.charset.Charset;
import java.util.Date;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.hamcrest.collection.IsCollectionWithSize;
import org.hamcrest.core.IsCollectionContaining;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.impl.NullClaim;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

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

	// Private PublicClaims

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
		DecodedJWT jwt = JWT.decode(
				"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOiIxMjM0NTY3ODkwIiwiaWF0IjoiMTIzNDU2Nzg5MCIsIm5iZiI6IjEyMzQ1Njc4OTAiLCJqdGkiOiJodHRwczovL2p3dC5pby8iLCJhdWQiOiJodHRwczovL2RvbWFpbi5hdXRoMC5jb20iLCJzdWIiOiJsb2dpbiIsImlzcyI6ImF1dGgwIiwiZXh0cmFDbGFpbSI6IkpvaG4gRG9lIn0.TX9Ct4feGp9YyeGK9Zl91tO0YBOrguJ4As9jeqgHdZQ");
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

	// Helper Methods

	private DecodedJWT customJWT(String jsonHeader, String jsonPayload, String signature) {
		String header = Base64.encodeBase64URLSafeString(jsonHeader.getBytes(Charset.forName("UTF-8")));
		String body = Base64.encodeBase64URLSafeString(jsonPayload.getBytes(Charset.forName("UTF-8")));
		return JWT.decode(String.format("%s.%s.%s", header, body, signature));
	}

}