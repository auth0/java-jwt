package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import org.apache.commons.codec.binary.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static com.auth0.jwt.PemUtils.readPrivateKeyFromFile;
import static com.auth0.jwt.PemUtils.readPublicKeyFromFile;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.junit.internal.matchers.ThrowableMessageMatcher.hasMessage;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RSAAlgorithmTest {

    private static final String PRIVATE_KEY_FILE = "src/test/resources/rsa-private.pem";
    private static final String PUBLIC_KEY_FILE = "src/test/resources/rsa-public.pem";
    private static final String INVALID_PUBLIC_KEY_FILE = "src/test/resources/rsa-public_invalid.pem";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    //Verify

    @Test
    public void shouldPassRSA256Verification() throws Exception {
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA";
        Algorithm algorithm = Algorithm.RSA256((RSAKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldPassRSA256VerificationWithBothKeys() throws Exception {
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA";
        Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"), (RSAPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailRSA256VerificationWithInvalidPublicKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withRSA");
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA";
        Algorithm algorithm = Algorithm.RSA256((RSAKey) readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE, "RSA"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailRSA256VerificationWhenUsingPrivateKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withRSA");
        exception.expectCause(isA(IllegalArgumentException.class));
        exception.expectCause(hasMessage(is("The given Public Key is null.")));
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA";
        Algorithm algorithm = Algorithm.RSA256((RSAKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldPassRSA384Verification() throws Exception {
        String jwt = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw";
        Algorithm algorithm = Algorithm.RSA384((RSAKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldPassRSA384VerificationWithBothKeys() throws Exception {
        String jwt = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw";
        Algorithm algorithm = Algorithm.RSA384((RSAPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"), (RSAPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailRSA384VerificationWithInvalidPublicKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withRSA");
        String jwt = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw";
        Algorithm algorithm = Algorithm.RSA384((RSAKey) readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE, "RSA"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailRSA384VerificationWhenUsingPrivateKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withRSA");
        exception.expectCause(isA(IllegalArgumentException.class));
        exception.expectCause(hasMessage(is("The given Public Key is null.")));
        String jwt = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw";
        Algorithm algorithm = Algorithm.RSA384((RSAKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldPassRSA512Verification() throws Exception {
        String jwt = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow";
        Algorithm algorithm = Algorithm.RSA512((RSAKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldPassRSA512VerificationWithBothKeys() throws Exception {
        String jwt = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow";
        Algorithm algorithm = Algorithm.RSA512((RSAPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"), (RSAPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailRSA512VerificationWithInvalidPublicKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withRSA");
        String jwt = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow";
        Algorithm algorithm = Algorithm.RSA512((RSAKey) readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE, "RSA"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldFailRSA512VerificationWhenUsingPrivateKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withRSA");
        exception.expectCause(isA(IllegalArgumentException.class));
        exception.expectCause(hasMessage(is("The given Public Key is null.")));
        String jwt = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow";
        Algorithm algorithm = Algorithm.RSA512((RSAKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldThrowWhenMacAlgorithmDoesNotExists() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: some-alg");
        exception.expectCause(isA(NoSuchAlgorithmException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.verifySignatureFor(anyString(), any(PublicKey.class), any(byte[].class), any(byte[].class)))
                .thenThrow(NoSuchAlgorithmException.class);

        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        Algorithm algorithm = new RSAAlgorithm(crypto, "some-alg", "some-algorithm", publicKey, privateKey);
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA";
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldThrowWhenThePublicKeyIsInvalid() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: some-alg");
        exception.expectCause(isA(InvalidKeyException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.verifySignatureFor(anyString(), any(PublicKey.class), any(byte[].class), any(byte[].class)))
                .thenThrow(InvalidKeyException.class);

        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        Algorithm algorithm = new RSAAlgorithm(crypto, "some-alg", "some-algorithm", publicKey, privateKey);
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA";
        AlgorithmUtils.verify(algorithm, jwt);
    }

    @Test
    public void shouldThrowWhenTheSignatureIsNotPrepared() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: some-alg");
        exception.expectCause(isA(SignatureException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.verifySignatureFor(anyString(), any(PublicKey.class), any(byte[].class), any(byte[].class)))
                .thenThrow(SignatureException.class);

        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        Algorithm algorithm = new RSAAlgorithm(crypto, "some-alg", "some-algorithm", publicKey, privateKey);
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA";
        AlgorithmUtils.verify(algorithm, jwt);
    }


    //Sign
    private static final String RS256Header = "eyJhbGciOiJSUzI1NiJ9";
    private static final String RS384Header = "eyJhbGciOiJSUzM4NCJ9";
    private static final String RS512Header = "eyJhbGciOiJSUzUxMiJ9";
    private static final String auth0IssPayload = "eyJpc3MiOiJhdXRoMCJ9";

    @Test
    public void shouldDoRSA256Signing() throws Exception {
        Algorithm algorithmSign = Algorithm.RSA256((RSAKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));
        Algorithm algorithmVerify = Algorithm.RSA256((RSAKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"));

        byte[] contentBytes = String.format("%s.%s", RS256Header, auth0IssPayload).getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = algorithmSign.sign(contentBytes);
        String signature = Base64.encodeBase64URLSafeString(signatureBytes);
        String expectedSignature = "ZB-Tr0vLtnf8I9fhSdSjU6HZei5xLYZQ6nZqM5O6Va0W9PgAqgRT7ShI9CjeYulRXPHvVmSl5EQuYuXdBzM0-H_3p_Nsl6tSMy4EyX2kkhEm6T0HhvarTh8CG0PCjn5p6FP5ZxWwhLcmRN70ItP6Z5MMO4CcJh1JrNxR4Fi4xQgt-CK2aVDMFXd-Br5yQiLVx1CX83w28OD9wssW3Rdltl5e66vCef0Ql6Q5I5e5F0nqGYT989a9fkNgLIx2F8k_az5x07BY59FV2SZg59nSiY7TZNjP8ot11Ew7HKRfPXOdh9eKRUVdhcxzqDePhyzKabU8TG5FP0SiWH5qVPfAgw";

        assertThat(signature, is(notNullValue()));
        assertThat(signature, is(expectedSignature));
        algorithmVerify.verify(contentBytes, signatureBytes);
    }

    @Test
    public void shouldDoRSA256SigningWithBothKeys() throws Exception {
        Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"), (RSAPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));

        byte[] contentBytes = String.format("%s.%s", RS256Header, auth0IssPayload).getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = algorithm.sign(contentBytes);
        String signature = Base64.encodeBase64URLSafeString(signatureBytes);
        String expectedSignature = "ZB-Tr0vLtnf8I9fhSdSjU6HZei5xLYZQ6nZqM5O6Va0W9PgAqgRT7ShI9CjeYulRXPHvVmSl5EQuYuXdBzM0-H_3p_Nsl6tSMy4EyX2kkhEm6T0HhvarTh8CG0PCjn5p6FP5ZxWwhLcmRN70ItP6Z5MMO4CcJh1JrNxR4Fi4xQgt-CK2aVDMFXd-Br5yQiLVx1CX83w28OD9wssW3Rdltl5e66vCef0Ql6Q5I5e5F0nqGYT989a9fkNgLIx2F8k_az5x07BY59FV2SZg59nSiY7TZNjP8ot11Ew7HKRfPXOdh9eKRUVdhcxzqDePhyzKabU8TG5FP0SiWH5qVPfAgw";

        assertThat(signature, is(notNullValue()));
        assertThat(signature, is(expectedSignature));
        algorithm.verify(contentBytes, signatureBytes);
    }

    @Test
    public void shouldFailOnRSA256SigningWhenUsingPublicKey() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: SHA256withRSA");
        exception.expectCause(isA(IllegalArgumentException.class));
        exception.expectCause(hasMessage(is("The given Private Key is null.")));

        Algorithm algorithm = Algorithm.RSA256((RSAKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"));
        algorithm.sign(new byte[0]);
    }

    @Test
    public void shouldDoRSA384Signing() throws Exception {
        Algorithm algorithmSign = Algorithm.RSA384((RSAKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));
        Algorithm algorithmVerify = Algorithm.RSA384((RSAKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"));

        byte[] contentBytes = String.format("%s.%s", RS384Header, auth0IssPayload).getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = algorithmSign.sign(contentBytes);
        String signature = Base64.encodeBase64URLSafeString(signatureBytes);
        String expectedSignature = "Jx1PaTBnjd_U56MNjifFcY7w9ImDbseg0y8Ijr2pSiA1_wzQb_wy9undaWfzR5YqdIAXvjS8AGuZUAzIoTG4KMgOgdVyYDz3l2jzj6wI-lgqfR5hTy1w1ruMUQ4_wobpdxAiJ4fEbg8Mi_GljOiCO-P1HilxKnpiOJZidR8MQGwTInsf71tOUkK4x5UsdmUueuZbaU-CL5kPnRfXmJj9CcdxZbD9oMlbo23dwkP5BNMrS2LwGGzc9C_-ypxrBIOVilG3WZxcSmuG86LjcZbnL6LBEfph5NmKBgQav147uipb_7umBEr1m2dYiB_9u606n3bcoo3rnsYYK_Xfi1GAEQ";

        assertThat(signature, is(notNullValue()));
        assertThat(signature, is(expectedSignature));
        algorithmVerify.verify(contentBytes, signatureBytes);
    }

    @Test
    public void shouldDoRSA384SigningWithBothKeys() throws Exception {
        Algorithm algorithm = Algorithm.RSA384((RSAPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"), (RSAPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));

        byte[] contentBytes = String.format("%s.%s", RS384Header, auth0IssPayload).getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = algorithm.sign(contentBytes);
        String signature = Base64.encodeBase64URLSafeString(signatureBytes);
        String expectedSignature = "Jx1PaTBnjd_U56MNjifFcY7w9ImDbseg0y8Ijr2pSiA1_wzQb_wy9undaWfzR5YqdIAXvjS8AGuZUAzIoTG4KMgOgdVyYDz3l2jzj6wI-lgqfR5hTy1w1ruMUQ4_wobpdxAiJ4fEbg8Mi_GljOiCO-P1HilxKnpiOJZidR8MQGwTInsf71tOUkK4x5UsdmUueuZbaU-CL5kPnRfXmJj9CcdxZbD9oMlbo23dwkP5BNMrS2LwGGzc9C_-ypxrBIOVilG3WZxcSmuG86LjcZbnL6LBEfph5NmKBgQav147uipb_7umBEr1m2dYiB_9u606n3bcoo3rnsYYK_Xfi1GAEQ";

        assertThat(signature, is(notNullValue()));
        assertThat(signature, is(expectedSignature));
        algorithm.verify(contentBytes, signatureBytes);
    }

    @Test
    public void shouldFailOnRSA384SigningWhenUsingPublicKey() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: SHA384withRSA");
        exception.expectCause(isA(IllegalArgumentException.class));
        exception.expectCause(hasMessage(is("The given Private Key is null.")));

        Algorithm algorithm = Algorithm.RSA384((RSAKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"));
        algorithm.sign(new byte[0]);
    }

    @Test
    public void shouldDoRSA512Signing() throws Exception {
        Algorithm algorithmSign = Algorithm.RSA512((RSAKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));
        Algorithm algorithmVerify = Algorithm.RSA512((RSAKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"));

        byte[] contentBytes = String.format("%s.%s", RS512Header, auth0IssPayload).getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = algorithmSign.sign(contentBytes);
        String signature = Base64.encodeBase64URLSafeString(signatureBytes);
        String expectedSignature = "THIPVYzNZ1Yo_dm0k1UELqV0txs3SzyMopCyHcLXOOdgYXF4MlGvBqu0CFvgSga72Sp5LpuC1Oesj40v_QDsp2GTGDeWnvvcv_eo-b0LPSpmT2h1Ibrmu-z70u2rKf28pkN-AJiMFqi8sit2kMIp1bwIVOovPvMTQKGFmova4Xwb3G526y_PeLlflW1h69hQTIVcI67ACEkAC-byjDnnYIklA-B4GWcggEoFwQRTdRjAUpifA6HOlvnBbZZlUd6KXwEydxVS-eh1odwPjB2_sfbyy5HnLsvNdaniiZQwX7QbwLNT4F72LctYdHHM1QCrID6bgfgYp9Ij9CRX__XDEA";

        assertThat(signature, is(notNullValue()));
        assertThat(signature, is(expectedSignature));
        algorithmVerify.verify(contentBytes, signatureBytes);
    }

    @Test
    public void shouldDoRSA512SigningWithBothKeys() throws Exception {
        Algorithm algorithm = Algorithm.RSA512((RSAPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"), (RSAPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));

        byte[] contentBytes = String.format("%s.%s", RS512Header, auth0IssPayload).getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = algorithm.sign(contentBytes);
        String signature = Base64.encodeBase64URLSafeString(signatureBytes);
        String expectedSignature = "THIPVYzNZ1Yo_dm0k1UELqV0txs3SzyMopCyHcLXOOdgYXF4MlGvBqu0CFvgSga72Sp5LpuC1Oesj40v_QDsp2GTGDeWnvvcv_eo-b0LPSpmT2h1Ibrmu-z70u2rKf28pkN-AJiMFqi8sit2kMIp1bwIVOovPvMTQKGFmova4Xwb3G526y_PeLlflW1h69hQTIVcI67ACEkAC-byjDnnYIklA-B4GWcggEoFwQRTdRjAUpifA6HOlvnBbZZlUd6KXwEydxVS-eh1odwPjB2_sfbyy5HnLsvNdaniiZQwX7QbwLNT4F72LctYdHHM1QCrID6bgfgYp9Ij9CRX__XDEA";

        assertThat(signature, is(notNullValue()));
        assertThat(signature, is(expectedSignature));
        algorithm.verify(contentBytes, signatureBytes);
    }

    @Test
    public void shouldFailOnRSA512SigningWhenUsingPublicKey() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: SHA512withRSA");
        exception.expectCause(isA(IllegalArgumentException.class));
        exception.expectCause(hasMessage(is("The given Private Key is null.")));

        Algorithm algorithm = Algorithm.RSA512((RSAKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"));
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

        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        Algorithm algorithm = new RSAAlgorithm(crypto, "some-alg", "some-algorithm", publicKey, privateKey);
        algorithm.sign(RS256Header.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void shouldThrowOnSignWhenThePrivateKeyIsInvalid() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm");
        exception.expectCause(isA(InvalidKeyException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.createSignatureFor(anyString(), any(PrivateKey.class), any(byte[].class)))
                .thenThrow(InvalidKeyException.class);

        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        Algorithm algorithm = new RSAAlgorithm(crypto, "some-alg", "some-algorithm", publicKey, privateKey);
        algorithm.sign(RS256Header.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void shouldThrowOnSignWhenTheSignatureIsNotPrepared() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm");
        exception.expectCause(isA(SignatureException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.createSignatureFor(anyString(), any(PrivateKey.class), any(byte[].class)))
                .thenThrow(SignatureException.class);

        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        Algorithm algorithm = new RSAAlgorithm(crypto, "some-alg", "some-algorithm", publicKey, privateKey);
        algorithm.sign(RS256Header.getBytes(StandardCharsets.UTF_8));
    }
}