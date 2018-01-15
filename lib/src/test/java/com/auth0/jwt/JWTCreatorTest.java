package com.auth0.jwt;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.Charset;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.ECDSAKeyProvider;
import com.auth0.jwt.interfaces.RSAKeyProvider;

public class JWTCreatorTest {

	private static final String PRIVATE_KEY_FILE_RSA = "src/test/resources/rsa-private.pem";
	private static final String PRIVATE_KEY_FILE_EC_256 = "src/test/resources/ec256-key-private.pem";

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Test
	public void shouldThrowWhenRequestingSignWithoutAlgorithm() throws Exception {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("The Algorithm cannot be null");
		JWTCreator.init().sign(null);
	}

	@SuppressWarnings("Convert2Diamond")
	@Test
	public void shouldAddHeaderClaim() throws Exception {
		Map<String, Object> header = new HashMap<String, Object>();
		header.put("asd", 123);
		String signed = JWTCreator.init().withHeader(header).sign(Algorithm.HMAC256("secret"));

		assertThat(signed, is(notNullValue()));
		String[] parts = signed.split("\\.");
		String headerJson = new String(Base64.decodeBase64(parts[0]), Charset.forName("UTF-8"));
		assertThat(headerJson, JsonMatcher.hasEntry("asd", 123));
	}

	@Test
	public void shouldAddKeyId() throws Exception {
		String signed = JWTCreator.init().withKeyId("56a8bd44da435300010000015f5ed").sign(Algorithm.HMAC256("secret"));

		assertThat(signed, is(notNullValue()));
		String[] parts = signed.split("\\.");
		String headerJson = new String(Base64.decodeBase64(parts[0]), Charset.forName("UTF-8"));
		assertThat(headerJson, JsonMatcher.hasEntry("kid", "56a8bd44da435300010000015f5ed"));
	}

	@Test
	public void shouldAddKeyIdIfAvailableFromRSAAlgorithms() throws Exception {
		RSAPrivateKey privateKey = (RSAPrivateKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_RSA, "RSA");
		RSAKeyProvider provider = mock(RSAKeyProvider.class);
		when(provider.getPrivateKeyId()).thenReturn("my-key-id");
		when(provider.getPrivateKey()).thenReturn(privateKey);

		String signed = JWTCreator.init().sign(Algorithm.RSA256(provider));

		assertThat(signed, is(notNullValue()));
		String[] parts = signed.split("\\.");
		String headerJson = new String(Base64.decodeBase64(parts[0]), Charset.forName("UTF-8"));
		assertThat(headerJson, JsonMatcher.hasEntry("kid", "my-key-id"));
	}

	@Test
	public void shouldNotOverwriteKeyIdIfAddedFromRSAAlgorithms() throws Exception {
		RSAPrivateKey privateKey = (RSAPrivateKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_RSA, "RSA");
		RSAKeyProvider provider = mock(RSAKeyProvider.class);
		when(provider.getPrivateKeyId()).thenReturn("my-key-id");
		when(provider.getPrivateKey()).thenReturn(privateKey);

		String signed = JWTCreator.init().withKeyId("real-key-id").sign(Algorithm.RSA256(provider));

		assertThat(signed, is(notNullValue()));
		String[] parts = signed.split("\\.");
		String headerJson = new String(Base64.decodeBase64(parts[0]), Charset.forName("UTF-8"));
		assertThat(headerJson, JsonMatcher.hasEntry("kid", "my-key-id"));
	}

	@Test
	public void shouldAddKeyIdIfAvailableFromECDSAAlgorithms() throws Exception {
		ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_EC_256, "EC");
		ECDSAKeyProvider provider = mock(ECDSAKeyProvider.class);
		when(provider.getPrivateKeyId()).thenReturn("my-key-id");
		when(provider.getPrivateKey()).thenReturn(privateKey);

		String signed = JWTCreator.init().sign(Algorithm.ECDSA256(provider));

		assertThat(signed, is(notNullValue()));
		String[] parts = signed.split("\\.");
		String headerJson = new String(Base64.decodeBase64(parts[0]), Charset.forName("UTF-8"));
		assertThat(headerJson, JsonMatcher.hasEntry("kid", "my-key-id"));
	}

	@Test
	public void shouldNotOverwriteKeyIdIfAddedFromECDSAAlgorithms() throws Exception {
		ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_EC_256, "EC");
		ECDSAKeyProvider provider = mock(ECDSAKeyProvider.class);
		when(provider.getPrivateKeyId()).thenReturn("my-key-id");
		when(provider.getPrivateKey()).thenReturn(privateKey);

		String signed = JWTCreator.init().withKeyId("real-key-id").sign(Algorithm.ECDSA256(provider));

		assertThat(signed, is(notNullValue()));
		String[] parts = signed.split("\\.");
		String headerJson = new String(Base64.decodeBase64(parts[0]), Charset.forName("UTF-8"));
		assertThat(headerJson, JsonMatcher.hasEntry("kid", "my-key-id"));
	}

	@Test
	public void shouldAddIssuer() throws Exception {
		String signed = JWTCreator.init().withIssuer("auth0").sign(Algorithm.HMAC256("secret"));

		assertThat(signed, is(notNullValue()));
		assertThat(TokenUtils.splitToken(signed)[1], is("eyJpc3MiOiJhdXRoMCJ9"));
	}

	@Test
	public void shouldAddSubject() throws Exception {
		String signed = JWTCreator.init().withSubject("1234567890").sign(Algorithm.HMAC256("secret"));

		assertThat(signed, is(notNullValue()));
		assertThat(TokenUtils.splitToken(signed)[1], is("eyJzdWIiOiIxMjM0NTY3ODkwIn0"));
	}

	@Test
	public void shouldAddAudience() throws Exception {
		String signed = JWTCreator.init().withAudience("Mark").sign(Algorithm.HMAC256("secret"));

		assertThat(signed, is(notNullValue()));
		assertThat(TokenUtils.splitToken(signed)[1], is("eyJhdWQiOiJNYXJrIn0"));

		String signedArr = JWTCreator.init().withAudience("Mark", "David").sign(Algorithm.HMAC256("secret"));

		assertThat(signedArr, is(notNullValue()));
		assertThat(TokenUtils.splitToken(signedArr)[1], is("eyJhdWQiOlsiTWFyayIsIkRhdmlkIl19"));
	}

	@Test
	public void shouldAddExpiresAt() throws Exception {
		String signed = JWTCreator.init().withExpiresAt(new Date(1477592000)).sign(Algorithm.HMAC256("secret"));

		assertThat(signed, is(notNullValue()));
		assertThat(TokenUtils.splitToken(signed)[1], is("eyJleHAiOjE0Nzc1OTJ9"));
	}

	@Test
	public void shouldAddNotBefore() throws Exception {
		String signed = JWTCreator.init().withNotBefore(new Date(1477592000)).sign(Algorithm.HMAC256("secret"));

		assertThat(signed, is(notNullValue()));
		assertThat(TokenUtils.splitToken(signed)[1], is("eyJuYmYiOjE0Nzc1OTJ9"));
	}

	@Test
	public void shouldAddIssuedAt() throws Exception {
		String signed = JWTCreator.init().withIssuedAt(new Date(1477592000)).sign(Algorithm.HMAC256("secret"));

		assertThat(signed, is(notNullValue()));
		assertThat(TokenUtils.splitToken(signed)[1], is("eyJpYXQiOjE0Nzc1OTJ9"));
	}

	@Test
	public void shouldAddJWTId() throws Exception {
		String signed = JWTCreator.init().withJWTId("jwt_id_123").sign(Algorithm.HMAC256("secret"));

		assertThat(signed, is(notNullValue()));
		assertThat(TokenUtils.splitToken(signed)[1], is("eyJqdGkiOiJqd3RfaWRfMTIzIn0"));
	}

	@Test
	public void shouldRemoveClaimWhenPassingNull() throws Exception {
		String signed = JWTCreator.init().withIssuer("iss").withIssuer(null).sign(Algorithm.HMAC256("secret"));

		assertThat(signed, is(notNullValue()));
		assertThat(TokenUtils.splitToken(signed)[1], is("e30"));
	}

	@Test
	public void shouldSetCorrectAlgorithmInTheHeader() throws Exception {
		String signed = JWTCreator.init().sign(Algorithm.HMAC256("secret"));

		assertThat(signed, is(notNullValue()));
		String[] parts = signed.split("\\.");
		String headerJson = new String(Base64.decodeBase64(parts[0]), Charset.forName("UTF-8"));
		assertThat(headerJson, JsonMatcher.hasEntry("alg", "HS256"));
	}

	@Test
	public void shouldSetCorrectTypeInTheHeader() throws Exception {
		String signed = JWTCreator.init().sign(Algorithm.HMAC256("secret"));

		assertThat(signed, is(notNullValue()));
		String[] parts = signed.split("\\.");
		String headerJson = new String(Base64.decodeBase64(parts[0]), Charset.forName("UTF-8"));
		assertThat(headerJson, JsonMatcher.hasEntry("typ", "JWT"));
	}

	@Test
	public void shouldSetEmptySignatureIfAlgorithmIsNone() throws Exception {
		String signed = JWTCreator.init().sign(Algorithm.none());
		assertThat(signed, is(notNullValue()));
		assertThat(TokenUtils.splitToken(signed)[2], is(""));
	}

	@Test
	public void shouldThrowOnNullCustomClaimName() throws Exception {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("The Custom Claim's name can't be null.");
		JWTCreator.init().withClaim(null, "value");
	}

	@Test
	public void shouldAcceptCustomClaimOfTypeString() throws Exception {
		String jwt = JWTCreator.init().withClaim("name", "value").sign(Algorithm.HMAC256("secret"));

		assertThat(jwt, is(notNullValue()));
		String[] parts = jwt.split("\\.");
		assertThat(parts[1], is("eyJuYW1lIjoidmFsdWUifQ"));
	}

	@Test
	public void shouldAcceptCustomClaimOfTypeInteger() throws Exception {
		String jwt = JWTCreator.init().withClaim("name", 123).sign(Algorithm.HMAC256("secret"));

		assertThat(jwt, is(notNullValue()));
		String[] parts = jwt.split("\\.");
		assertThat(parts[1], is("eyJuYW1lIjoxMjN9"));
	}

	@Test
	public void shouldAcceptCustomClaimOfTypeLong() throws Exception {
		String jwt = JWTCreator.init().withClaim("name", Long.MAX_VALUE).sign(Algorithm.HMAC256("secret"));

		assertThat(jwt, is(notNullValue()));
		String[] parts = jwt.split("\\.");
		assertThat(parts[1], is("eyJuYW1lIjo5MjIzMzcyMDM2ODU0Nzc1ODA3fQ"));
	}

	@Test
	public void shouldAcceptCustomClaimOfTypeDouble() throws Exception {
		String jwt = JWTCreator.init().withClaim("name", 23.45).sign(Algorithm.HMAC256("secret"));

		assertThat(jwt, is(notNullValue()));
		String[] parts = jwt.split("\\.");
		assertThat(parts[1], is("eyJuYW1lIjoyMy40NX0"));
	}

	@Test
	public void shouldAcceptCustomClaimOfTypeBoolean() throws Exception {
		String jwt = JWTCreator.init().withClaim("name", true).sign(Algorithm.HMAC256("secret"));

		assertThat(jwt, is(notNullValue()));
		String[] parts = jwt.split("\\.");
		assertThat(parts[1], is("eyJuYW1lIjp0cnVlfQ"));
	}

	@Test
	public void shouldAcceptCustomClaimOfTypeDate() throws Exception {
		Date date = new Date(1478891521000L);
		String jwt = JWTCreator.init().withClaim("name", date).sign(Algorithm.HMAC256("secret"));

		assertThat(jwt, is(notNullValue()));
		String[] parts = jwt.split("\\.");
		assertThat(parts[1], is("eyJuYW1lIjoxNDc4ODkxNTIxfQ"));
	}

	@Test
	public void shouldAcceptCustomArrayClaimOfTypeString() throws Exception {
		String jwt = JWTCreator.init().withArrayClaim("name", new String[] { "text", "123", "true" }).sign(Algorithm.HMAC256("secret"));

		assertThat(jwt, is(notNullValue()));
		String[] parts = jwt.split("\\.");
		assertThat(parts[1], is("eyJuYW1lIjpbInRleHQiLCIxMjMiLCJ0cnVlIl19"));
	}

	@Test
	public void shouldAcceptCustomArrayClaimOfTypeInteger() throws Exception {
		String jwt = JWTCreator.init().withArrayClaim("name", new Integer[] { 1, 2, 3 }).sign(Algorithm.HMAC256("secret"));

		assertThat(jwt, is(notNullValue()));
		String[] parts = jwt.split("\\.");
		assertThat(parts[1], is("eyJuYW1lIjpbMSwyLDNdfQ"));
	}

	@Test
	public void shouldAcceptCustomArrayClaimOfTypeLong() throws Exception {
		String jwt = JWTCreator.init().withArrayClaim("name", new Long[] { 1L, 2L, 3L }).sign(Algorithm.HMAC256("secret"));

		assertThat(jwt, is(notNullValue()));
		String[] parts = jwt.split("\\.");
		assertThat(parts[1], is("eyJuYW1lIjpbMSwyLDNdfQ"));
	}
}