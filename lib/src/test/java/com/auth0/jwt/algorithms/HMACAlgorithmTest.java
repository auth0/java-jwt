package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import org.apache.commons.codec.binary.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class HMACAlgorithmTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    // Verify

    @Test
    public void shouldPassHMAC256Verification() throws Exception {
        String jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        Algorithm algorithm = Algorithm.HMAC256("secret");
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailHMAC256VerificationWithInvalidSecret() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA256");
        String jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        Algorithm algorithm = Algorithm.HMAC256("not_real_secret");
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldPassHMAC384Verification() throws Exception {
        String jwt = "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw";
        Algorithm algorithm = Algorithm.HMAC384("secret");
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailHMAC384VerificationWithInvalidSecret() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA384");
        String jwt = "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw";
        Algorithm algorithm = Algorithm.HMAC384("not_real_secret");
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldPassHMAC512Verification() throws Exception {
        String jwt = "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw";
        Algorithm algorithm = Algorithm.HMAC512("secret");
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailHMAC512VerificationWithInvalidSecret() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA512");
        String jwt = "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw";
        Algorithm algorithm = Algorithm.HMAC512("not_real_secret");
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldThrowOnVerifyWhenSignatureAlgorithmDoesNotExists() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: some-alg");
        exception.expectCause(isA(NoSuchAlgorithmException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.verifySignatureFor(anyString(), any(byte[].class), any(byte[].class), any(byte[].class)))
                .thenThrow(NoSuchAlgorithmException.class);

        Algorithm algorithm = new HMACAlgorithm(crypto, "some-alg", "some-algorithm", "secret");
        String jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldThrowOnVerifyhenTheSecretIsInvalid() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: some-alg");
        exception.expectCause(isA(InvalidKeyException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.verifySignatureFor(anyString(), any(byte[].class), any(byte[].class), any(byte[].class)))
                .thenThrow(InvalidKeyException.class);

        Algorithm algorithm = new HMACAlgorithm(crypto, "some-alg", "some-algorithm", "secret");
        String jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        AlgorithmUtils.verify(algorithm, jwt);
    }

    // Sign

    private static final String HS256Header = "eyJhbGciOiJIUzI1NiJ9";
    private static final String HS384Header = "eyJhbGciOiJIUzM4NCJ9";
    private static final String HS512Header = "eyJhbGciOiJIUzUxMiJ9";
    private static final String auth0IssPayload = "eyJpc3MiOiJhdXRoMCJ9";

    @Test
    public void shouldDoHMAC256Signing() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        byte[] contentBytes = String.format("%s.%s", HS256Header, auth0IssPayload).getBytes();
        byte[] signatureBytes = algorithm.sign(contentBytes);
        String signature = Base64.encodeBase64URLSafeString(signatureBytes);
        String expectedSignature = "s69x7Mmu4JqwmdxiK6sesALO7tcedbFsKEEITUxw9ho";

        assertThat(signatureBytes, is(notNullValue()));
        assertThat(signature, is(expectedSignature));
        algorithm.verify(contentBytes, signatureBytes);
    }

    @Test
    public void shouldDoHMAC384Signing() throws Exception {
        Algorithm algorithm = Algorithm.HMAC384("secret");
        byte[] contentBytes = String.format("%s.%s", HS384Header, auth0IssPayload).getBytes();
        byte[] signatureBytes = algorithm.sign(contentBytes);
        String signature = Base64.encodeBase64URLSafeString(signatureBytes);
        String expectedSignature = "4-y2Gxz_foN0jAOFimmBPF7DWxf4AsjM20zxNkHg8Zah5Q64G42P9GfjmUp4Hldt";

        assertThat(signatureBytes, is(notNullValue()));
        assertThat(signature, is(expectedSignature));
        algorithm.verify(contentBytes, signatureBytes);
    }

    @Test
    public void shouldDoHMAC512Signing() throws Exception {
        Algorithm algorithm = Algorithm.HMAC512("secret");
        byte[] contentBytes = String.format("%s.%s", HS512Header, auth0IssPayload).getBytes();
        byte[] signatureBytes = algorithm.sign(contentBytes);
        String signature = Base64.encodeBase64URLSafeString(signatureBytes);
        String expectedSignature = "OXWyxmf-VcVo8viOiTFfLaEy6mrQqLEos5R82Xsx8mtFxQadJAQ1aVniIWN8qT2GNE_pMQPcdzk4x7Cqxsp1dw";

        assertThat(signatureBytes, is(notNullValue()));
        assertThat(signature, is(expectedSignature));
        algorithm.verify(contentBytes, signatureBytes);
    }

    @Test
    public void shouldThrowOnSignWhenSignatureAlgorithmDoesNotExists() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm");
        exception.expectCause(isA(NoSuchAlgorithmException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.createSignatureFor(anyString(), any(byte[].class), any(byte[].class)))
                .thenThrow(NoSuchAlgorithmException.class);

        Algorithm algorithm = new HMACAlgorithm(crypto, "some-alg", "some-algorithm", "secret");
        algorithm.sign(new byte[0]);
    }

    @Test
    public void shouldThrowOnSignWhenTheSecretIsInvalid() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm");
        exception.expectCause(isA(InvalidKeyException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.createSignatureFor(anyString(), any(byte[].class), any(byte[].class)))
                .thenThrow(InvalidKeyException.class);

        Algorithm algorithm = new HMACAlgorithm(crypto, "some-alg", "some-algorithm", "secret");
        algorithm.sign(new byte[0]);
    }

}