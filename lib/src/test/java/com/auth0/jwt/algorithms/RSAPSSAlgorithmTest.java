package com.auth0.jwt.algorithms;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.Provider;
import java.security.Security;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static com.auth0.jwt.PemUtils.readPrivateKeyFromFile;
import static com.auth0.jwt.PemUtils.readPublicKeyFromFile;
import static com.auth0.jwt.algorithms.CryptoTestHelper.asJWT;
import static com.auth0.jwt.algorithms.CryptoTestHelper.assertSignaturePresent;

/**
 * Round-trip tests for the RSASSA-PSS (PS256/PS384/PS512) algorithms.
 * <p>
 * BouncyCastle is registered as a provider so these tests also pass on Java 8, whose built-in
 * providers do not implement RSASSA-PSS. On Java 11+ the built-in provider would suffice, but
 * registering BouncyCastle keeps the test behavior identical across the supported Java versions.
 */
public class RSAPSSAlgorithmTest {

    private static final String PRIVATE_KEY_FILE = "src/test/resources/rsa-private.pem";
    private static final String PUBLIC_KEY_FILE = "src/test/resources/rsa-public.pem";
    private static final String INVALID_PUBLIC_KEY_FILE = "src/test/resources/rsa-public_invalid.pem";

    private static final String PS256Header = "eyJhbGciOiJQUzI1NiJ9";
    private static final String PS384Header = "eyJhbGciOiJQUzM4NCJ9";
    private static final String PS512Header = "eyJhbGciOiJQUzUxMiJ9";
    private static final String auth0IssPayload = "eyJpc3MiOiJhdXRoMCJ9";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private static final Provider bcProvider = new BouncyCastleProvider();

    @BeforeClass
    public static void setUp() {
        Security.insertProviderAt(bcProvider, 1);
    }

    @AfterClass
    public static void tearDown() {
        Security.removeProvider(bcProvider.getName());
    }

    @Test
    public void shouldSignAndVerifyPS256WithBothKeys() throws Exception {
        Algorithm algorithm = Algorithm.RSA256PSS(
                (RSAPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"),
                (RSAPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));

        String jwt = asJWT(algorithm, PS256Header, auth0IssPayload);

        assertSignaturePresent(jwt);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldSignWithPrivateKeyAndVerifyWithPublicKeyPS256() throws Exception {
        Algorithm signer = Algorithm.RSA256PSS((RSAKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));
        Algorithm verifier = Algorithm.RSA256PSS((RSAKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"));

        String jwt = asJWT(signer, PS256Header, auth0IssPayload);

        assertSignaturePresent(jwt);
        verifier.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldSignAndVerifyPS384WithBothKeys() throws Exception {
        Algorithm algorithm = Algorithm.RSA384PSS(
                (RSAPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"),
                (RSAPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));

        String jwt = asJWT(algorithm, PS384Header, auth0IssPayload);

        assertSignaturePresent(jwt);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldSignAndVerifyPS512WithBothKeys() throws Exception {
        Algorithm algorithm = Algorithm.RSA512PSS(
                (RSAPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"),
                (RSAPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));

        String jwt = asJWT(algorithm, PS512Header, auth0IssPayload);

        assertSignaturePresent(jwt);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldProduceNonDeterministicSignatures() throws Exception {
        Algorithm algorithm = Algorithm.RSA256PSS(
                (RSAPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"),
                (RSAPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));

        String firstJwt = asJWT(algorithm, PS256Header, auth0IssPayload);
        String secondJwt = asJWT(algorithm, PS256Header, auth0IssPayload);

        String firstSignature = firstJwt.substring(firstJwt.lastIndexOf('.') + 1);
        String secondSignature = secondJwt.substring(secondJwt.lastIndexOf('.') + 1);
        org.hamcrest.MatcherAssert.assertThat(firstSignature,
                org.hamcrest.CoreMatchers.is(org.hamcrest.CoreMatchers.not(secondSignature)));
        algorithm.verify(JWT.decode(firstJwt));
        algorithm.verify(JWT.decode(secondJwt));
    }

    @Test
    public void shouldFailPS256VerificationWithInvalidPublicKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: RSASSA-PSS");

        Algorithm signer = Algorithm.RSA256PSS((RSAKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));
        String jwt = asJWT(signer, PS256Header, auth0IssPayload);

        Algorithm verifier = Algorithm.RSA256PSS((RSAKey) readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE, "RSA"));
        verifier.verify(JWT.decode(jwt));
    }
}
