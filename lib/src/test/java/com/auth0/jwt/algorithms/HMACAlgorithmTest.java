package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.SignatureVerificationException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.hamcrest.Matchers.isA;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class HMACAlgorithmTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

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
    public void shouldThrowWhenSignatureAlgorithmDoesNotExists() throws Exception {
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
    public void shouldThrowWhenTheSecretIsInvalid() throws Exception {
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

}