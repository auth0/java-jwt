package com.auth0.jwt.algorithms;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.interfaces.ECKey;

import static com.auth0.jwt.PemUtils.readPublicKeyFromFile;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

public class NoneAlgorithmTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldPassNoneVerification() {
        Algorithm algorithm = Algorithm.none();
        String jwt = "eyJhbGciOiJub25lIiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.";
        algorithm.verify(JWT.decode(jwt));

        algorithm.verify(JWT.decode(jwt), false);
        algorithm.verify(JWT.decode(jwt), true);
    }

    @Test
    public void shouldFailNoneVerificationWhenTokenHasTwoParts() {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("The token was expected to have 3 parts, but got 2.");
        String jwt = "eyJhbGciOiJub25lIiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9";
        Algorithm algorithm = Algorithm.none();
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldFailNoneVerificationWhenSignatureIsPresent() {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: none");
        String jwt = "eyJhbGciOiJub25lIiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.Ox-WRXRaGAuWt2KfPvWiGcCrPqZtbp_4OnQzZXaTfss";
        Algorithm algorithm = Algorithm.none();
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldReturnNullSigningKeyId() {
        assertThat(Algorithm.none().getSigningKeyId(), is(nullValue()));
    }

    @Test
    public void shouldThrowWhenSignatureNotValidBase64() {
        exception.expect(SignatureVerificationException.class);
        exception.expectCause(isA(IllegalArgumentException.class));

        String jwt = "eyJhbGciOiJub25lIiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.Ox-WRXRaGAuWt2KfPvW+iGcCrPqZtbp_4OnQzZXaTfss";
        Algorithm algorithm = Algorithm.none();
        algorithm.verify(JWT.decode(jwt));
    }
}
