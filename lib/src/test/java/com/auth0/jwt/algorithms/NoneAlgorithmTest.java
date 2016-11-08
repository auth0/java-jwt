package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.SignatureVerificationException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class NoneAlgorithmTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldPassNoneVerification() throws Exception {
        String[] parts = new String[]{"eyJhbGciOiJub25lIiwiY3R5IjoiSldUIn0", "eyJpc3MiOiJhdXRoMCJ9", ""};
        Algorithm algorithm = Algorithm.none();
        algorithm.verify(parts);
    }

    @Test
    public void shouldFailNoneVerificationWhenSignatureIsPresent() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: none");
        String jwt = "eyJhbGciOiJub25lIiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.Ox-WRXRaGAuWt2KfPvWiGcCrPqZtbp_4OnQzZXaTfss";
        Algorithm algorithm = Algorithm.none();
        algorithm.verify(jwt.split("\\."));
    }

}