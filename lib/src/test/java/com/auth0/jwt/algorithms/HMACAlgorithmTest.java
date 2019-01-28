package com.auth0.jwt.algorithms;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.codec.binary.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import static com.auth0.jwt.PemUtils.readPrivateKeyFromFile;
import static com.auth0.jwt.PemUtils.readPublicKeyFromFile;
import static com.auth0.jwt.algorithms.CryptoTestHelper.asJWT;
import static com.auth0.jwt.algorithms.CryptoTestHelper.assertSignaturePresent;
import static com.auth0.jwt.algorithms.CryptoTestHelper.assertSignatureValue;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class HMACAlgorithmTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    // Verify

    @Test
    public void shouldGetStringBytes() throws Exception {
        String text = "abcdef123456!@#$%^";
        byte[] expectedBytes = text.getBytes("UTF-8");
        assertTrue(Arrays.equals(expectedBytes, HMACAlgorithm.getSecretBytes(text)));
    }

    @Test
    public void shouldPassHMAC256Verification() throws Exception {
        String jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        Algorithm algorithmString = Algorithm.HMAC256("secret");
        Algorithm algorithmBytes = Algorithm.HMAC256("secret".getBytes(StandardCharsets.UTF_8));
        DecodedJWT decoded = JWT.decode(jwt);
        algorithmString.verify(decoded);
        algorithmBytes.verify(decoded);
    }

    @Test
    public void shouldFailHMAC256VerificationWithInvalidSecretString() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA256");
        String jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        Algorithm algorithm = Algorithm.HMAC256("not_real_secret");
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldFailHMAC256VerificationWithInvalidSecretBytes() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA256");
        String jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        Algorithm algorithm = Algorithm.HMAC256("not_real_secret".getBytes(StandardCharsets.UTF_8));
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldPassHMAC384Verification() throws Exception {
        String jwt = "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw";
        Algorithm algorithmString = Algorithm.HMAC384("secret");
        Algorithm algorithmBytes = Algorithm.HMAC384("secret".getBytes(StandardCharsets.UTF_8));
        DecodedJWT decoded = JWT.decode(jwt);
        algorithmString.verify(decoded);
        algorithmBytes.verify(decoded);
    }

    @Test
    public void shouldFailHMAC384VerificationWithInvalidSecretString() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA384");
        String jwt = "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw";
        Algorithm algorithm = Algorithm.HMAC384("not_real_secret");
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldFailHMAC384VerificationWithInvalidSecretBytes() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA384");
        String jwt = "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw";
        Algorithm algorithm = Algorithm.HMAC384("not_real_secret".getBytes(StandardCharsets.UTF_8));
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldPassHMAC512Verification() throws Exception {
        String jwt = "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw";
        Algorithm algorithmString = Algorithm.HMAC512("secret");
        Algorithm algorithmBytes = Algorithm.HMAC512("secret".getBytes(StandardCharsets.UTF_8));
        DecodedJWT decoded = JWT.decode(jwt);
        algorithmString.verify(decoded);
        algorithmBytes.verify(decoded);
    }

    @Test
    public void shouldFailHMAC512VerificationWithInvalidSecretString() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA512");
        String jwt = "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw";
        Algorithm algorithm = Algorithm.HMAC512("not_real_secret");
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldFailHMAC512VerificationWithInvalidSecretBytes() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA512");
        String jwt = "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw";
        Algorithm algorithm = Algorithm.HMAC512("not_real_secret".getBytes(StandardCharsets.UTF_8));
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldThrowOnVerifyWhenSignatureAlgorithmDoesNotExists() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: some-alg");
        exception.expectCause(isA(NoSuchAlgorithmException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.verifySignatureFor(anyString(), any(byte[].class), any(String.class), any(String.class), any(byte[].class)))
                .thenThrow(NoSuchAlgorithmException.class);

        Algorithm algorithm = new HMACAlgorithm(crypto, "some-alg", "some-algorithm", "secret".getBytes(StandardCharsets.UTF_8));
        String jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldThrowOnVerifyWhenTheSecretIsInvalid() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: some-alg");
        exception.expectCause(isA(InvalidKeyException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.verifySignatureFor(anyString(), any(byte[].class), any(String.class), any(String.class), any(byte[].class)))
                .thenThrow(InvalidKeyException.class);

        Algorithm algorithm = new HMACAlgorithm(crypto, "some-alg", "some-algorithm", "secret".getBytes(StandardCharsets.UTF_8));
        String jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        algorithm.verify(JWT.decode(jwt));
    }

    // Sign

    private static final String HS256Header = "eyJhbGciOiJIUzI1NiJ9";
    private static final String HS384Header = "eyJhbGciOiJIUzM4NCJ9";
    private static final String HS512Header = "eyJhbGciOiJIUzUxMiJ9";
    private static final String auth0IssPayload = "eyJpc3MiOiJhdXRoMCJ9";

    @Test
    public void shouldDoHMAC256SigningWithBytes() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes(StandardCharsets.UTF_8));

        String jwt = asJWT(algorithm, HS256Header, auth0IssPayload);
        String expectedSignature = "s69x7Mmu4JqwmdxiK6sesALO7tcedbFsKEEITUxw9ho";

        assertSignaturePresent(jwt);
        assertSignatureValue(jwt, expectedSignature);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldDoHMAC384SigningWithBytes() throws Exception {
        Algorithm algorithm = Algorithm.HMAC384("secret".getBytes(StandardCharsets.UTF_8));

        String jwt = asJWT(algorithm, HS384Header, auth0IssPayload);
        String expectedSignature = "4-y2Gxz_foN0jAOFimmBPF7DWxf4AsjM20zxNkHg8Zah5Q64G42P9GfjmUp4Hldt";

        assertSignaturePresent(jwt);
        assertSignatureValue(jwt, expectedSignature);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldDoHMAC512SigningWithBytes() throws Exception {
        Algorithm algorithm = Algorithm.HMAC512("secret".getBytes(StandardCharsets.UTF_8));

        String jwt = asJWT(algorithm, HS512Header, auth0IssPayload);
        String expectedSignature = "OXWyxmf-VcVo8viOiTFfLaEy6mrQqLEos5R82Xsx8mtFxQadJAQ1aVniIWN8qT2GNE_pMQPcdzk4x7Cqxsp1dw";

        assertSignaturePresent(jwt);
        assertSignatureValue(jwt, expectedSignature);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldDoHMAC256SigningWithString() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");

        String jwt = asJWT(algorithm, HS256Header, auth0IssPayload);
        String expectedSignature = "s69x7Mmu4JqwmdxiK6sesALO7tcedbFsKEEITUxw9ho";

        assertSignaturePresent(jwt);
        assertSignatureValue(jwt, expectedSignature);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldDoHMAC384SigningWithString() throws Exception {
        Algorithm algorithm = Algorithm.HMAC384("secret");

        String jwt = asJWT(algorithm, HS384Header, auth0IssPayload);
        String expectedSignature = "4-y2Gxz_foN0jAOFimmBPF7DWxf4AsjM20zxNkHg8Zah5Q64G42P9GfjmUp4Hldt";

        assertSignaturePresent(jwt);
        assertSignatureValue(jwt, expectedSignature);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldDoHMAC512SigningWithString() throws Exception {
        Algorithm algorithm = Algorithm.HMAC512("secret");

        String jwt = asJWT(algorithm ,HS512Header, auth0IssPayload);
        String expectedSignature = "OXWyxmf-VcVo8viOiTFfLaEy6mrQqLEos5R82Xsx8mtFxQadJAQ1aVniIWN8qT2GNE_pMQPcdzk4x7Cqxsp1dw";

        assertSignaturePresent(jwt);
        assertSignatureValue(jwt, expectedSignature);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldThrowOnSignWhenSignatureAlgorithmDoesNotExists() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm");
        exception.expectCause(isA(NoSuchAlgorithmException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.createSignatureFor(anyString(), any(byte[].class), any(byte[].class), any(byte[].class)))
                .thenThrow(NoSuchAlgorithmException.class);

        Algorithm algorithm = new HMACAlgorithm(crypto, "some-alg", "some-algorithm", "secret".getBytes(StandardCharsets.UTF_8));
        algorithm.sign(new byte[0], new byte[0]);
    }

    @Test
    public void shouldThrowOnSignWhenTheSecretIsInvalid() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm");
        exception.expectCause(isA(InvalidKeyException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.createSignatureFor(anyString(), any(byte[].class), any(byte[].class), any(byte[].class)))
                .thenThrow(InvalidKeyException.class);

        Algorithm algorithm = new HMACAlgorithm(crypto, "some-alg", "some-algorithm", "secret".getBytes(StandardCharsets.UTF_8));
        algorithm.sign(new byte[0], new byte[0]);
    }

    @Test
    public void shouldReturnNullSigningKeyId() throws Exception {
        assertThat(Algorithm.HMAC256("secret").getSigningKeyId(), is(nullValue()));
    }

    @Test
    public void shouldBeEqualSignatureMethodResults() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");

        byte[] header = new byte[]{0x00, 0x01, 0x02};
        byte[] payload = new byte[]{0x04, 0x05, 0x06};

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        bout.write(header);
        bout.write('.');
        bout.write(payload);

        assertThat(algorithm.sign(bout.toByteArray()), is(algorithm.sign(header, payload)));
    }

}