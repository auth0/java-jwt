package com.auth0.jwt;

import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;

import static com.auth0.jwt.pem.PemReader.readPublicKey;
import static junit.framework.TestCase.assertNotNull;

/**
 * RS256 Verification Checks
 */
public class JWTVerifierRsa256Test {

    private final static String RESOURCES_DIR = "src/test/resources/auth0-pem/";
    private final static String MISMATCHED_RESOURCES_DIR = "src/test/resources/test-pem/";
    private final static String PUBLIC_KEY_PEM_FILENAME = "key.pem";
    private final static String MISMATCHED_PUBLIC_KEY_PEM_FILENAME = "test-auth0.pem";



    /**
     * Here we pass in a public key that does not correspond to the private key that was used to sign the JWT Token
     */
    @Test(expected = SignatureException.class)
    public void shouldFailOnInvalidSignature() throws Exception {
        final String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFVTkVRelZCTXpoRk1FVTNRMFZGTURJNFFqYzROakJDTkRSQ1JFRkNSalkzUWpnMFJEVXlOZyJ9" +
                "." +
                "eyJyb2xlcyI6WyJST0xFX0FETUlOIl0sInVzZXJfaWQiOiJhdXRoMHw1NzcxMGU5ZDE0MWIwN2YyMmU3NDNhYzciLCJlbWFpbCI6ImFyY3NlbGRvbit0cm5AZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlzcyI6Imh0dHBzOi8vYWppbG9uMS5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NTc3MTBlOWQxNDFiMDdmMjJlNzQzYWM3IiwiYXVkIjoibm5ld1NobHBHVDFBbkZpY1ExUGlKWXdheENuejE4eUIiLCJleHAiOjE0Njc3MDk5OTMsImlhdCI6MTQ2NzY3Mzk5M30" +
                "." +
                "gQML78V8H6WN3MSN1QhrFG4AxNTdFChPBQxrnuqPF0iBvf35v_z9oDzTERaPBDWFHzWT17h0ADxpl7tCIo43k0FoFie6RHa5j82iHnOKPhcqM5hArfKDYk3G5gc30lVmFiMm8PX8WKzDExygLqXZVnIzfB-EmcJWW_2fLiFEMpNC8KDTBVAiyds_n5kiGmW6F_QpLt11af3BDy71tg2fuqkyJE6pEHd1HsTHNCFQzWt7GevVB0HouJS099p6GphsH3kIhmAvHp5j267uYv49sndiUaLq7bL6GZnzv8dhzgQlucHvNaIZ6m6m6n4t43cjUxSrO0ZP9Crv9NBDJme0cA";
        final PublicKey publicKey = readPublicKey(MISMATCHED_RESOURCES_DIR + MISMATCHED_PUBLIC_KEY_PEM_FILENAME);
        assertNotNull(publicKey);
        new JWTVerifier(publicKey, "audience").verifySignature(token.split("\\."), Algorithm.RS256);
    }

    /**
     * Here we pass in a public key that correctly corresponds to the private key that was used to sign the JWT Token
     */
    @Test
    public void shouldVerifySignature() throws Exception {
        final String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFVTkVRelZCTXpoRk1FVTNRMFZGTURJNFFqYzROakJDTkRSQ1JFRkNSalkzUWpnMFJEVXlOZyJ9" +
                "." +
                "eyJyb2xlcyI6WyJST0xFX0FETUlOIl0sInVzZXJfaWQiOiJhdXRoMHw1NzcxMGU5ZDE0MWIwN2YyMmU3NDNhYzciLCJlbWFpbCI6ImFyY3NlbGRvbit0cm5AZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlzcyI6Imh0dHBzOi8vYWppbG9uMS5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NTc3MTBlOWQxNDFiMDdmMjJlNzQzYWM3IiwiYXVkIjoibm5ld1NobHBHVDFBbkZpY1ExUGlKWXdheENuejE4eUIiLCJleHAiOjE0Njc3MDk5OTMsImlhdCI6MTQ2NzY3Mzk5M30" +
                "." +
                "gQML78V8H6WN3MSN1QhrFG4AxNTdFChPBQxrnuqPF0iBvf35v_z9oDzTERaPBDWFHzWT17h0ADxpl7tCIo43k0FoFie6RHa5j82iHnOKPhcqM5hArfKDYk3G5gc30lVmFiMm8PX8WKzDExygLqXZVnIzfB-EmcJWW_2fLiFEMpNC8KDTBVAiyds_n5kiGmW6F_QpLt11af3BDy71tg2fuqkyJE6pEHd1HsTHNCFQzWt7GevVB0HouJS099p6GphsH3kIhmAvHp5j267uYv49sndiUaLq7bL6GZnzv8dhzgQlucHvNaIZ6m6m6n4t43cjUxSrO0ZP9Crv9NBDJme0cA";
        final PublicKey publicKey = readPublicKey(RESOURCES_DIR + PUBLIC_KEY_PEM_FILENAME);
        assertNotNull(publicKey);
        new JWTVerifier(publicKey, "audience").verifySignature(token.split("\\."), Algorithm.RS256);
    }

    /**
     * Here we modify the signature on an otherwise legal JWT Token and check verification using the correct Public Key fails
     */
    @Test(expected = SignatureException.class)
    public void shouldFailOnInvalidJWTTokenSignature() throws Exception {
        final String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFVTkVRelZCTXpoRk1FVTNRMFZGTURJNFFqYzROakJDTkRSQ1JFRkNSalkzUWpnMFJEVXlOZyJ9" +
                "." +
                "eyJyb2xlcyI6WyJST0xFX0FETUlOIl0sInVzZXJfaWQiOiJhdXRoMHw1NzcxMGU5ZDE0MWIwN2YyMmU3NDNhYzciLCJlbWFpbCI6ImFyY3NlbGRvbit0cm5AZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlzcyI6Imh0dHBzOi8vYWppbG9uMS5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NTc3MTBlOWQxNDFiMDdmMjJlNzQzYWM3IiwiYXVkIjoibm5ld1NobHBHVDFBbkZpY1ExUGlKWXdheENuejE4eUIiLCJleHAiOjE0Njc3MDk5OTMsImlhdCI6MTQ2NzY3Mzk5M30" +
                "." +
                "XXXXX8V8H6WN3MSN1QhrFG4AxNTdFChPBQxrnuqPF0iBvf35v_z9oDzTERaPBDWFHzWT17h0ADxpl7tCIo43k0FoFie6RHa5j82iHnOKPhcqM5hArfKDYk3G5gc30lVmFiMm8PX8WKzDExygLqXZVnIzfB-EmcJWW_2fLiFEMpNC8KDTBVAiyds_n5kiGmW6F_QpLt11af3BDy71tg2fuqkyJE6pEHd1HsTHNCFQzWt7GevVB0HouJS099p6GphsH3kIhmAvHp5j267uYv49sndiUaLq7bL6GZnzv8dhzgQlucHvNaIZ6m6m6n4t43cjUxSrO0ZP9Crv9NBDJme0cA";
        final PublicKey publicKey = readPublicKey(RESOURCES_DIR + PUBLIC_KEY_PEM_FILENAME);
        assertNotNull(publicKey);
        new JWTVerifier(publicKey, "audience").verifySignature(token.split("\\."), Algorithm.RS256);
    }

    /**
     * Here we modify the payload section on an otherwise legal JWT Token and check verification using the correct Public Key and
     * unaltered JWT signature (which now doesn't match the payload) fails
     */
    @Test(expected = SignatureException.class)
    public void shouldFailOnInvalidJWTTokenPayload() throws Exception {
        final String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFVTkVRelZCTXpoRk1FVTNRMFZGTURJNFFqYzROakJDTkRSQ1JFRkNSalkzUWpnMFJEVXlOZyJ9" +
                "." +
                "XXXXX2xlcyI6WyJST0xFX0FETUlOIl0sInVzZXJfaWQiOiJhdXRoMHw1NzcxMGU5ZDE0MWIwN2YyMmU3NDNhYzciLCJlbWFpbCI6ImFyY3NlbGRvbit0cm5AZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlzcyI6Imh0dHBzOi8vYWppbG9uMS5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NTc3MTBlOWQxNDFiMDdmMjJlNzQzYWM3IiwiYXVkIjoibm5ld1NobHBHVDFBbkZpY1ExUGlKWXdheENuejE4eUIiLCJleHAiOjE0Njc3MDk5OTMsImlhdCI6MTQ2NzY3Mzk5M30" +
                "." +
                "gQML78V8H6WN3MSN1QhrFG4AxNTdFChPBQxrnuqPF0iBvf35v_z9oDzTERaPBDWFHzWT17h0ADxpl7tCIo43k0FoFie6RHa5j82iHnOKPhcqM5hArfKDYk3G5gc30lVmFiMm8PX8WKzDExygLqXZVnIzfB-EmcJWW_2fLiFEMpNC8KDTBVAiyds_n5kiGmW6F_QpLt11af3BDy71tg2fuqkyJE6pEHd1HsTHNCFQzWt7GevVB0HouJS099p6GphsH3kIhmAvHp5j267uYv49sndiUaLq7bL6GZnzv8dhzgQlucHvNaIZ6m6m6n4t43cjUxSrO0ZP9Crv9NBDJme0cA";
        final PublicKey publicKey = readPublicKey(RESOURCES_DIR + PUBLIC_KEY_PEM_FILENAME);
        assertNotNull(publicKey);
        new JWTVerifier(publicKey, "audience").verifySignature(token.split("\\."), Algorithm.RS256);
    }

    @Test(expected = IllegalStateException.class)
    public void shouldFailWithJwtThaHasTamperedAlgorithm() throws Exception {
        final File file = new File(RESOURCES_DIR + PUBLIC_KEY_PEM_FILENAME);
        final byte[] data = Files.readAllBytes(file.toPath());
        JWTSigner signer = new JWTSigner(data);
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "userid");
        JWTSigner.Options options = new JWTSigner.Options();
        options.setAlgorithm(Algorithm.HS256);
        String jwt = signer.sign(claims, options);
        new JWTVerifier(data).verify(jwt);
        final PublicKey publicKey = readPublicKey(RESOURCES_DIR + PUBLIC_KEY_PEM_FILENAME);
        new JWTVerifier(publicKey).verify(jwt);
    }
}

