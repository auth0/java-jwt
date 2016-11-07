package com.auth0.jwtdecodejava.algorithms;

import com.auth0.jwtdecodejava.exceptions.SignatureVerificationException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.PublicKey;

import static com.auth0.jwtdecodejava.PemUtils.readPublicKeyFromFile;

public class ECDSAAlgorithmTest {

    private static final String PUBLIC_KEY_FILE_256 = "src/test/resources/ec256-key-public.pem";
    private static final String INVALID_PUBLIC_KEY_FILE_256 = "src/test/resources/ec256-key-public-invalid.pem";

    private static final String PUBLIC_KEY_FILE_384 = "src/test/resources/ec384-key-public.pem";
    private static final String INVALID_PUBLIC_KEY_FILE_384 = "src/test/resources/ec384-key-public-invalid.pem";

    private static final String PUBLIC_KEY_FILE_512 = "src/test/resources/ec512-key-public.pem";
    private static final String INVALID_PUBLIC_KEY_FILE_512 = "src/test/resources/ec512-key-public-invalid.pem";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    //JOSE Signatures obtained using Node 'jwa' lib: https://github.com/brianloveswords/node-jwa
    //DER Signatures obtained from source JOSE signature using 'ecdsa-sig-formatter' lib: https://github.com/Brightspace/node-ecdsa-sig-formatter
    
    @Test
    public void shouldPassECDSA256VerificationWithJOSESignature() throws Exception {
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g";
        PublicKey key = readPublicKeyFromFile(PUBLIC_KEY_FILE_256, "EC");
        Algorithm algorithm = Algorithm.ECDSA256(key);
        algorithm.verify(jwt.split("\\."));
    }

    @Test
    public void shouldPassECDSA256VerificationWithDERSignature() throws Exception {
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.MEYCIQDiJWTf5jS/hFPj/0hpCWn7x1n/h+xPMjKWCs9MMusS9AIhAMcFPJVLe2A9uvb8hl8sRO2IpGoKDRpDmyH14ixNPAHW";
        PublicKey key = readPublicKeyFromFile(PUBLIC_KEY_FILE_256, "EC");
        Algorithm algorithm = Algorithm.ECDSA256(key);
        algorithm.verify(jwt.split("\\."));
    }

    @Test
    public void shouldFailECDSA256VerificationWithInvalidPublicKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withECDSA");
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.W9qfN1b80B9hnMo49WL8THrOsf1vEjOhapeFemPMGySzxTcgfyudS5esgeBTO908X5SLdAr5jMwPUPBs9b6nNg";
        Algorithm algorithm = Algorithm.ECDSA256(readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE_256, "EC"));
        algorithm.verify(jwt.split("\\."));
    }

    @Test
    public void shouldPassECDSA384VerificationWithJOSESignature() throws Exception {
        String jwt = "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhdXRoMCJ9.50UU5VKNdF1wfykY8jQBKpvuHZoe6IZBJm5NvoB8bR-hnRg6ti-CHbmvoRtlLfnHfwITa_8cJMy6TenMC2g63GQHytc8rYoXqbwtS4R0Ko_AXbLFUmfxnGnMC6v4MS_z";
        PublicKey key = readPublicKeyFromFile(PUBLIC_KEY_FILE_384, "EC");
        Algorithm algorithm = Algorithm.ECDSA384(key);
        algorithm.verify(jwt.split("\\."));
    }

    @Test
    public void shouldPassECDSA384VerificationWithDERSignature() throws Exception {
        String jwt = "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhdXRoMCJ9.MGUCMQDnRRTlUo10XXB/KRjyNAEqm+4dmh7ohkEmbk2+gHxtH6GdGDq2L4Idua+hG2Ut+ccCMH8CE2v/HCTMuk3pzAtoOtxkB8rXPK2KF6m8LUuEdCqPwF2yxVJn8ZxpzAur+DEv8w==";
        PublicKey key = readPublicKeyFromFile(PUBLIC_KEY_FILE_384, "EC");
        Algorithm algorithm = Algorithm.ECDSA384(key);
        algorithm.verify(jwt.split("\\."));
    }

    @Test
    public void shouldFailECDSA384VerificationWithInvalidPublicKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withECDSA");
        String jwt = "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhdXRoMCJ9._k5h1KyO-NE0R2_HAw0-XEc0bGT5atv29SxHhOGC9JDqUHeUdptfCK_ljQ01nLVt2OQWT2SwGs-TuyHDFmhPmPGFZ9wboxvq_ieopmYqhQilNAu-WF-frioiRz9733fU";
        Algorithm algorithm = Algorithm.ECDSA384(readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE_384, "EC"));
        algorithm.verify(jwt.split("\\."));
    }

    @Test
    public void shouldPassECDSA512VerificationWithJOSESignature() throws Exception {
        String jwt = "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.AeCJPDIsSHhwRSGZCY6rspi8zekOw0K9qYMNridP1Fu9uhrA1QrG-EUxXlE06yvmh2R7Rz0aE7kxBwrnq8L8aOBCAYAsqhzPeUvyp8fXjjgs0Eto5I0mndE2QHlgcMSFASyjHbU8wD2Rq7ZNzGQ5b2MZfpv030WGUajT-aZYWFUJHVg2";
        PublicKey key = readPublicKeyFromFile(PUBLIC_KEY_FILE_512, "EC");
        Algorithm algorithm = Algorithm.ECDSA512(key);
        algorithm.verify(jwt.split("\\."));
    }

    @Test
    public void shouldPassECDSA512VerificationWithDERSignature() throws Exception {
        String jwt = "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.MIGIAkIB4Ik8MixIeHBFIZkJjquymLzN6Q7DQr2pgw2uJ0/UW726GsDVCsb4RTFeUTTrK+aHZHtHPRoTuTEHCuerwvxo4EICQgGALKocz3lL8qfH1444LNBLaOSNJp3RNkB5YHDEhQEsox21PMA9kau2TcxkOW9jGX6b9N9FhlGo0/mmWFhVCR1YNg==";
        PublicKey key = readPublicKeyFromFile(PUBLIC_KEY_FILE_512, "EC");
        Algorithm algorithm = Algorithm.ECDSA512(key);
        algorithm.verify(jwt.split("\\."));
    }

    @Test
    public void shouldFailECDSA512VerificationWithInvalidPublicKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withECDSA");
        String jwt = "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.AZgdopFFsN0amCSs2kOucXdpylD31DEm5ChK1PG0_gq5Mf47MrvVph8zHSVuvcrXzcE1U3VxeCg89mYW1H33Y-8iAF0QFkdfTUQIWKNObH543WNMYYssv3OtOj0znPv8atDbaF8DMYAtcT1qdmaSJRhx-egRE9HGZkinPh9CfLLLt58X";
        Algorithm algorithm = Algorithm.ECDSA512(readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE_512, "EC"));
        algorithm.verify(jwt.split("\\."));
    }

}