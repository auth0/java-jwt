package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import org.apache.commons.codec.binary.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import static com.auth0.jwt.PemUtils.readPrivateKeyFromFile;
import static com.auth0.jwt.PemUtils.readPublicKeyFromFile;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.junit.internal.matchers.ThrowableMessageMatcher.hasMessage;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ECDSAAlgorithmTest {

    private static final String PRIVATE_KEY_FILE_256 = "src/test/resources/ec256-key-private.pem";
    private static final String PUBLIC_KEY_FILE_256 = "src/test/resources/ec256-key-public.pem";
    private static final String INVALID_PUBLIC_KEY_FILE_256 = "src/test/resources/ec256-key-public-invalid.pem";

    private static final String PRIVATE_KEY_FILE_384 = "src/test/resources/ec384-key-private.pem";
    private static final String PUBLIC_KEY_FILE_384 = "src/test/resources/ec384-key-public.pem";
    private static final String INVALID_PUBLIC_KEY_FILE_384 = "src/test/resources/ec384-key-public-invalid.pem";

    private static final String PRIVATE_KEY_FILE_512 = "src/test/resources/ec512-key-private.pem";
    private static final String PUBLIC_KEY_FILE_512 = "src/test/resources/ec512-key-public.pem";
    private static final String INVALID_PUBLIC_KEY_FILE_512 = "src/test/resources/ec512-key-public-invalid.pem";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    //JOSE Signatures obtained using Node 'jwa' lib: https://github.com/brianloveswords/node-jwa
    //DER Signatures obtained from source JOSE signature using 'ecdsa-sig-formatter' lib: https://github.com/Brightspace/node-ecdsa-sig-formatter

    // Verify

    @Test
    public void shouldPassECDSA256VerificationWithJOSESignature() throws Exception {
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g";
        ECKey key = (ECKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_256, "EC");
        Algorithm algorithm = Algorithm.ECDSA256(key);
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldPassECDSA256VerificationWithDERSignature() throws Exception {
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.MEYCIQDiJWTf5jS/hFPj/0hpCWn7x1n/h+xPMjKWCs9MMusS9AIhAMcFPJVLe2A9uvb8hl8sRO2IpGoKDRpDmyH14ixNPAHW";
        ECKey key = (ECKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_256, "EC");
        Algorithm algorithm = Algorithm.ECDSA256(key);
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldPassECDSA256VerificationWithJOSESignatureWithBothKeys() throws Exception {
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g";
        Algorithm algorithm = Algorithm.ECDSA256((ECPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_256, "EC"), (ECPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE_256, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldPassECDSA256VerificationWithDERSignatureWithBothKeys() throws Exception {
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.MEYCIQDiJWTf5jS/hFPj/0hpCWn7x1n/h+xPMjKWCs9MMusS9AIhAMcFPJVLe2A9uvb8hl8sRO2IpGoKDRpDmyH14ixNPAHW";
        Algorithm algorithm = Algorithm.ECDSA256((ECPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_256, "EC"), (ECPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE_256, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailECDSA256VerificationWithInvalidPublicKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withECDSA");
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.W9qfN1b80B9hnMo49WL8THrOsf1vEjOhapeFemPMGySzxTcgfyudS5esgeBTO908X5SLdAr5jMwPUPBs9b6nNg";
        Algorithm algorithm = Algorithm.ECDSA256((ECKey) readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE_256, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailECDSA256VerificationWhenUsingPrivateKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withECDSA");
        exception.expectCause(isA(IllegalStateException.class));
        exception.expectCause(hasMessage(is("The given Public Key is null.")));
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.W9qfN1b80B9hnMo49WL8THrOsf1vEjOhapeFemPMGySzxTcgfyudS5esgeBTO908X5SLdAr5jMwPUPBs9b6nNg";
        Algorithm algorithm = Algorithm.ECDSA256((ECKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE_256, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailECDSA256VerificationOnInvalidSignatureLength() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withECDSA");
        exception.expectCause(isA(SignatureException.class));
        exception.expectCause(hasMessage(is("The signature length was invalid. Expected 64 bytes but received 63")));

        byte[] bytes = new byte[63];
        new SecureRandom().nextBytes(bytes);
        String signature = Base64.encodeBase64URLSafeString(bytes);
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9." + signature;
        Algorithm algorithm = Algorithm.ECDSA256((ECKey) readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE_256, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailECDSA256VerificationOnInvalidJOSESignature() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withECDSA");

        byte[] bytes = new byte[64];
        new SecureRandom().nextBytes(bytes);
        String signature = Base64.encodeBase64URLSafeString(bytes);
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9." + signature;
        Algorithm algorithm = Algorithm.ECDSA256((ECKey) readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE_256, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailECDSA256VerificationOnInvalidDERSignature() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withECDSA");

        byte[] bytes = new byte[64];
        bytes[0] = 0x30;
        new SecureRandom().nextBytes(bytes);
        String signature = Base64.encodeBase64URLSafeString(bytes);
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9." + signature;
        Algorithm algorithm = Algorithm.ECDSA256((ECKey) readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE_256, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldPassECDSA384VerificationWithJOSESignature() throws Exception {
        String jwt = "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhdXRoMCJ9.50UU5VKNdF1wfykY8jQBKpvuHZoe6IZBJm5NvoB8bR-hnRg6ti-CHbmvoRtlLfnHfwITa_8cJMy6TenMC2g63GQHytc8rYoXqbwtS4R0Ko_AXbLFUmfxnGnMC6v4MS_z";
        ECKey key = (ECKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_384, "EC");
        Algorithm algorithm = Algorithm.ECDSA384(key);
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldPassECDSA384VerificationWithDERSignature() throws Exception {
        String jwt = "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhdXRoMCJ9.MGUCMQDnRRTlUo10XXB/KRjyNAEqm+4dmh7ohkEmbk2+gHxtH6GdGDq2L4Idua+hG2Ut+ccCMH8CE2v/HCTMuk3pzAtoOtxkB8rXPK2KF6m8LUuEdCqPwF2yxVJn8ZxpzAur+DEv8w==";
        ECKey key = (ECKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_384, "EC");
        Algorithm algorithm = Algorithm.ECDSA384(key);
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldPassECDSA384VerificationWithJOSESignatureWithBothKeys() throws Exception {
        String jwt = "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhdXRoMCJ9.50UU5VKNdF1wfykY8jQBKpvuHZoe6IZBJm5NvoB8bR-hnRg6ti-CHbmvoRtlLfnHfwITa_8cJMy6TenMC2g63GQHytc8rYoXqbwtS4R0Ko_AXbLFUmfxnGnMC6v4MS_z";
        Algorithm algorithm = Algorithm.ECDSA384((ECPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_384, "EC"), (ECPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE_384, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldPassECDSA384VerificationWithDERSignatureWithBothKeys() throws Exception {
        String jwt = "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhdXRoMCJ9.MGUCMQDnRRTlUo10XXB/KRjyNAEqm+4dmh7ohkEmbk2+gHxtH6GdGDq2L4Idua+hG2Ut+ccCMH8CE2v/HCTMuk3pzAtoOtxkB8rXPK2KF6m8LUuEdCqPwF2yxVJn8ZxpzAur+DEv8w==";
        Algorithm algorithm = Algorithm.ECDSA384((ECPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_384, "EC"), (ECPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE_384, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailECDSA384VerificationWithInvalidPublicKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withECDSA");
        String jwt = "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhdXRoMCJ9._k5h1KyO-NE0R2_HAw0-XEc0bGT5atv29SxHhOGC9JDqUHeUdptfCK_ljQ01nLVt2OQWT2SwGs-TuyHDFmhPmPGFZ9wboxvq_ieopmYqhQilNAu-WF-frioiRz9733fU";
        Algorithm algorithm = Algorithm.ECDSA384((ECKey) readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE_384, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailECDSA384VerificationWhenUsingPrivateKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withECDSA");
        exception.expectCause(isA(IllegalStateException.class));
        exception.expectCause(hasMessage(is("The given Public Key is null.")));
        String jwt = "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhdXRoMCJ9._k5h1KyO-NE0R2_HAw0-XEc0bGT5atv29SxHhOGC9JDqUHeUdptfCK_ljQ01nLVt2OQWT2SwGs-TuyHDFmhPmPGFZ9wboxvq_ieopmYqhQilNAu-WF-frioiRz9733fU";
        Algorithm algorithm = Algorithm.ECDSA384((ECKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE_384, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailECDSA384VerificationOnInvalidSignatureLength() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withECDSA");
        exception.expectCause(isA(SignatureException.class));
        exception.expectCause(hasMessage(is("The signature length was invalid. Expected 96 bytes but received 95")));

        byte[] bytes = new byte[95];
        new SecureRandom().nextBytes(bytes);
        String signature = Base64.encodeBase64URLSafeString(bytes);
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9." + signature;
        Algorithm algorithm = Algorithm.ECDSA384((ECKey) readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE_384, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailECDSA384VerificationOnInvalidJOSESignature() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withECDSA");

        byte[] bytes = new byte[96];
        new SecureRandom().nextBytes(bytes);
        String signature = Base64.encodeBase64URLSafeString(bytes);
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9." + signature;
        Algorithm algorithm = Algorithm.ECDSA384((ECKey) readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE_384, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailECDSA384VerificationOnInvalidDERSignature() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withECDSA");

        byte[] bytes = new byte[96];
        new SecureRandom().nextBytes(bytes);
        bytes[0] = 0x30;
        String signature = Base64.encodeBase64URLSafeString(bytes);
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9." + signature;
        Algorithm algorithm = Algorithm.ECDSA384((ECKey) readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE_384, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldPassECDSA512VerificationWithJOSESignature() throws Exception {
        String jwt = "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.AeCJPDIsSHhwRSGZCY6rspi8zekOw0K9qYMNridP1Fu9uhrA1QrG-EUxXlE06yvmh2R7Rz0aE7kxBwrnq8L8aOBCAYAsqhzPeUvyp8fXjjgs0Eto5I0mndE2QHlgcMSFASyjHbU8wD2Rq7ZNzGQ5b2MZfpv030WGUajT-aZYWFUJHVg2";
        ECKey key = (ECKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_512, "EC");
        Algorithm algorithm = Algorithm.ECDSA512(key);
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldPassECDSA512VerificationWithDERSignature() throws Exception {
        String jwt = "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.MIGIAkIB4Ik8MixIeHBFIZkJjquymLzN6Q7DQr2pgw2uJ0/UW726GsDVCsb4RTFeUTTrK+aHZHtHPRoTuTEHCuerwvxo4EICQgGALKocz3lL8qfH1444LNBLaOSNJp3RNkB5YHDEhQEsox21PMA9kau2TcxkOW9jGX6b9N9FhlGo0/mmWFhVCR1YNg==";
        ECKey key = (ECKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_512, "EC");
        Algorithm algorithm = Algorithm.ECDSA512(key);
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldPassECDSA512VerificationWithJOSESignatureWithBothKeys() throws Exception {
        String jwt = "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.AeCJPDIsSHhwRSGZCY6rspi8zekOw0K9qYMNridP1Fu9uhrA1QrG-EUxXlE06yvmh2R7Rz0aE7kxBwrnq8L8aOBCAYAsqhzPeUvyp8fXjjgs0Eto5I0mndE2QHlgcMSFASyjHbU8wD2Rq7ZNzGQ5b2MZfpv030WGUajT-aZYWFUJHVg2";
        Algorithm algorithm = Algorithm.ECDSA512((ECPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_512, "EC"), (ECPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE_512, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldPassECDSA512VerificationWithDERSignatureWithBothKeys() throws Exception {
        String jwt = "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.MIGIAkIB4Ik8MixIeHBFIZkJjquymLzN6Q7DQr2pgw2uJ0/UW726GsDVCsb4RTFeUTTrK+aHZHtHPRoTuTEHCuerwvxo4EICQgGALKocz3lL8qfH1444LNBLaOSNJp3RNkB5YHDEhQEsox21PMA9kau2TcxkOW9jGX6b9N9FhlGo0/mmWFhVCR1YNg==";
        Algorithm algorithm = Algorithm.ECDSA512((ECPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_512, "EC"), (ECPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE_512, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailECDSA512VerificationWithInvalidPublicKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withECDSA");
        String jwt = "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.AZgdopFFsN0amCSs2kOucXdpylD31DEm5ChK1PG0_gq5Mf47MrvVph8zHSVuvcrXzcE1U3VxeCg89mYW1H33Y-8iAF0QFkdfTUQIWKNObH543WNMYYssv3OtOj0znPv8atDbaF8DMYAtcT1qdmaSJRhx-egRE9HGZkinPh9CfLLLt58X";
        Algorithm algorithm = Algorithm.ECDSA512((ECKey) readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE_512, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailECDSA512VerificationWhenUsingPrivateKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withECDSA");
        exception.expectCause(isA(IllegalStateException.class));
        exception.expectCause(hasMessage(is("The given Public Key is null.")));
        String jwt = "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.AZgdopFFsN0amCSs2kOucXdpylD31DEm5ChK1PG0_gq5Mf47MrvVph8zHSVuvcrXzcE1U3VxeCg89mYW1H33Y-8iAF0QFkdfTUQIWKNObH543WNMYYssv3OtOj0znPv8atDbaF8DMYAtcT1qdmaSJRhx-egRE9HGZkinPh9CfLLLt58X";
        Algorithm algorithm = Algorithm.ECDSA512((ECKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE_512, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailECDSA512VerificationOnInvalidSignatureLength() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withECDSA");
        exception.expectCause(isA(SignatureException.class));
        exception.expectCause(hasMessage(is("The signature length was invalid. Expected 132 bytes but received 131")));

        byte[] bytes = new byte[131];
        new SecureRandom().nextBytes(bytes);
        String signature = Base64.encodeBase64URLSafeString(bytes);
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9." + signature;
        Algorithm algorithm = Algorithm.ECDSA512((ECKey) readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE_512, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailECDSA512VerificationOnInvalidJOSESignature() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withECDSA");

        byte[] bytes = new byte[132];
        new SecureRandom().nextBytes(bytes);
        String signature = Base64.encodeBase64URLSafeString(bytes);
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9." + signature;
        Algorithm algorithm = Algorithm.ECDSA512((ECKey) readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE_512, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailECDSA512VerificationOnInvalidDERSignature() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withECDSA");

        byte[] bytes = new byte[132];
        new SecureRandom().nextBytes(bytes);
        bytes[0] = 0x30;
        String signature = Base64.encodeBase64URLSafeString(bytes);
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9." + signature;
        Algorithm algorithm = Algorithm.ECDSA512((ECKey) readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE_512, "EC"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailJOSEToDERConversionOnInvalidJOSESignatureLength() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withECDSA");
        exception.expectCause(isA(SignatureException.class));
        exception.expectCause(hasMessage(is("Invalid ECDSA signature format")));

        byte[] bytes = new byte[256];
        new SecureRandom().nextBytes(bytes);
        String signature = Base64.encodeBase64URLSafeString(bytes);
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9." + signature;

        ECPublicKey publicKey = (ECPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_256, "EC");
        ECPrivateKey privateKey = mock(ECPrivateKey.class);
        Algorithm algorithm = new ECDSAAlgorithm("ES256", "SHA256withECDSA", 128, publicKey, privateKey);
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldThrowOnVerifyWhenSignatureAlgorithmDoesNotExists() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: some-alg");
        exception.expectCause(isA(NoSuchAlgorithmException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.verifySignatureFor(anyString(), any(PublicKey.class), any(byte[].class), any(byte[].class)))
                .thenThrow(NoSuchAlgorithmException.class);

        ECPublicKey publicKey = mock(ECPublicKey.class);
        ECPrivateKey privateKey = mock(ECPrivateKey.class);
        Algorithm algorithm = new ECDSAAlgorithm(crypto, "some-alg", "some-algorithm", 32, publicKey, privateKey);
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g";
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldThrowOnVerifyWhenThePublicKeyIsInvalid() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: some-alg");
        exception.expectCause(isA(InvalidKeyException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.verifySignatureFor(anyString(), any(PublicKey.class), any(byte[].class), any(byte[].class)))
                .thenThrow(InvalidKeyException.class);

        ECPublicKey publicKey = mock(ECPublicKey.class);
        ECPrivateKey privateKey = mock(ECPrivateKey.class);
        Algorithm algorithm = new ECDSAAlgorithm(crypto, "some-alg", "some-algorithm", 32, publicKey, privateKey);
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g";
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldThrowOnVerifyWhenTheSignatureIsNotPrepared() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: some-alg");
        exception.expectCause(isA(SignatureException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.verifySignatureFor(anyString(), any(PublicKey.class), any(byte[].class), any(byte[].class)))
                .thenThrow(SignatureException.class);

        ECPublicKey publicKey = mock(ECPublicKey.class);
        ECPrivateKey privateKey = mock(ECPrivateKey.class);
        Algorithm algorithm = new ECDSAAlgorithm(crypto, "some-alg", "some-algorithm", 32, publicKey, privateKey);
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g";
        AlgorithmUtils.verify(algorithm, jwt);
    }

    //Sign
    private static final String ES256Header = "eyJhbGciOiJFUzI1NiJ9";
    private static final String ES384Header = "eyJhbGciOiJFUzM4NCJ9";
    private static final String ES512Header = "eyJhbGciOiJFUzUxMiJ9";
    private static final String auth0IssPayload = "eyJpc3MiOiJhdXRoMCJ9";

    @Test
    public void shouldDoECDSA256Signing() throws Exception {
        Algorithm algorithmSign = Algorithm.ECDSA256((ECKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE_256, "EC"));
        Algorithm algorithmVerify = Algorithm.ECDSA256((ECKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_256, "EC"));
        byte[] contentBytes = String.format("%s.%s", ES256Header, auth0IssPayload).getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = algorithmSign.sign(contentBytes);

        assertThat(signatureBytes, is(notNullValue()));
        algorithmVerify.verify(contentBytes, signatureBytes);
    }

    @Test
    public void shouldDoECDSA256SigningWithBothKeys() throws Exception {
        Algorithm algorithm = Algorithm.ECDSA256((ECPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_256, "EC"), (ECPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE_256, "EC"));
        byte[] contentBytes = String.format("%s.%s", ES256Header, auth0IssPayload).getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = algorithm.sign(contentBytes);

        assertThat(signatureBytes, is(notNullValue()));
        algorithm.verify(contentBytes, signatureBytes);
    }

    @Test
    public void shouldFailOnECDSA256SigningWhenUsingPublicKey() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: SHA256withECDSA");
        exception.expectCause(isA(IllegalStateException.class));
        exception.expectCause(hasMessage(is("The given Private Key is null.")));

        Algorithm algorithm = Algorithm.ECDSA256((ECKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_256, "EC"));
        algorithm.sign(new byte[0]);
    }

    @Test
    public void shouldDoECDSA384Signing() throws Exception {
        Algorithm algorithmSign = Algorithm.ECDSA384((ECKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE_384, "EC"));
        Algorithm algorithmVerify = Algorithm.ECDSA384((ECKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_384, "EC"));
        byte[] contentBytes = String.format("%s.%s", ES384Header, auth0IssPayload).getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = algorithmSign.sign(contentBytes);

        assertThat(signatureBytes, is(notNullValue()));
        algorithmVerify.verify(contentBytes, signatureBytes);
    }

    @Test
    public void shouldDoECDSA384SigningWithBothKeys() throws Exception {
        Algorithm algorithm = Algorithm.ECDSA384((ECPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_384, "EC"), (ECPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE_384, "EC"));
        byte[] contentBytes = String.format("%s.%s", ES384Header, auth0IssPayload).getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = algorithm.sign(contentBytes);

        assertThat(signatureBytes, is(notNullValue()));
        algorithm.verify(contentBytes, signatureBytes);
    }

    @Test
    public void shouldFailOnECDSA384SigningWhenUsingPublicKey() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: SHA384withECDSA");
        exception.expectCause(isA(IllegalStateException.class));
        exception.expectCause(hasMessage(is("The given Private Key is null.")));

        Algorithm algorithm = Algorithm.ECDSA384((ECKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_384, "EC"));
        algorithm.sign(new byte[0]);
    }

    @Test
    public void shouldDoECDSA512Signing() throws Exception {
        Algorithm algorithmSign = Algorithm.ECDSA512((ECKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE_512, "EC"));
        Algorithm algorithmVerify = Algorithm.ECDSA512((ECKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_512, "EC"));
        byte[] contentBytes = String.format("%s.%s", ES512Header, auth0IssPayload).getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = algorithmSign.sign(contentBytes);

        assertThat(signatureBytes, is(notNullValue()));
        algorithmVerify.verify(contentBytes, signatureBytes);
    }

    @Test
    public void shouldDoECDSA512SigningWithBothKeys() throws Exception {
        Algorithm algorithm = Algorithm.ECDSA512((ECPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_512, "EC"), (ECPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE_512, "EC"));
        byte[] contentBytes = String.format("%s.%s", ES512Header, auth0IssPayload).getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = algorithm.sign(contentBytes);

        assertThat(signatureBytes, is(notNullValue()));
        algorithm.verify(contentBytes, signatureBytes);
    }

    @Test
    public void shouldFailOnECDSA512SigningWhenUsingPublicKey() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: SHA512withECDSA");
        exception.expectCause(isA(IllegalStateException.class));
        exception.expectCause(hasMessage(is("The given Private Key is null.")));

        Algorithm algorithm = Algorithm.ECDSA512((ECKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_512, "EC"));
        algorithm.sign(new byte[0]);
    }

    @Test
    public void shouldThrowOnSignWhenSignatureAlgorithmDoesNotExists() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm");
        exception.expectCause(isA(NoSuchAlgorithmException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.createSignatureFor(anyString(), any(PrivateKey.class), any(byte[].class)))
                .thenThrow(NoSuchAlgorithmException.class);

        ECPublicKey publicKey = mock(ECPublicKey.class);
        ECPrivateKey privateKey = mock(ECPrivateKey.class);
        Algorithm algorithm = new ECDSAAlgorithm(crypto, "some-alg", "some-algorithm", 32, publicKey, privateKey);
        algorithm.sign(ES256Header.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void shouldThrowOnSignWhenThePrivateKeyIsInvalid() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm");
        exception.expectCause(isA(InvalidKeyException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.createSignatureFor(anyString(), any(PrivateKey.class), any(byte[].class)))
                .thenThrow(InvalidKeyException.class);

        ECPublicKey publicKey = mock(ECPublicKey.class);
        ECPrivateKey privateKey = mock(ECPrivateKey.class);
        Algorithm algorithm = new ECDSAAlgorithm(crypto, "some-alg", "some-algorithm", 32, publicKey, privateKey);
        algorithm.sign(ES256Header.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void shouldThrowOnSignWhenTheSignatureIsNotPrepared() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm");
        exception.expectCause(isA(SignatureException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.createSignatureFor(anyString(), any(PrivateKey.class), any(byte[].class)))
                .thenThrow(SignatureException.class);

        ECPublicKey publicKey = mock(ECPublicKey.class);
        ECPrivateKey privateKey = mock(ECPrivateKey.class);
        Algorithm algorithm = new ECDSAAlgorithm(crypto, "some-alg", "some-algorithm", 32, publicKey, privateKey);
        algorithm.sign(ES256Header.getBytes(StandardCharsets.UTF_8));
    }
}