package com.auth0.jwt.algorithms;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.ByteArrayOutputStream;
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
import static com.auth0.jwt.algorithms.CryptoTestHelper.*;

@SuppressWarnings("deprecation")
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
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldPassRSA256VerificationWithBothKeys() throws Exception {
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA";
        Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"), (RSAPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldPassRSA256VerificationWithProvidedPublicKey() throws Exception {
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        PublicKey publicKey = readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA");
        when(provider.getPublicKeyById("my-key-id")).thenReturn((RSAPublicKey) publicKey);
        String jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJhdXRoMCJ9.jXrbue3xJmnzWH9kU-uGeCTtgbQEKbch8uHd4Z52t86ncNyepfusl_bsyLJIcxMwK7odRzKiSE9efV9JaRSEDODDBdMeCzODFx82uBM7e46T1NLVSmjYIM7Hcfh81ZeTIk-hITvgtL6hvTdeJWOCZAB0bs18qSVW5SvursRUhY38xnhuNI6HOHCtqp7etxWAu6670L53I3GtXsmi6bXIzv_0v1xZcAFg4HTvXxfhfj3oCqkSs2nC27mHxBmQtmZKWmXk5HzVUyPRwTUWx5wHPT_hCsGer-CMCAyGsmOg466y1KDqf7ogpMYojfVZGWBsyA39LO1oWZ4Ryomkn8t5Vg";
        Algorithm algorithm = Algorithm.RSA256(provider);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldFailRSA256VerificationWhenProvidedPublicKeyIsNull() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withRSA");
        exception.expectCause(isA(IllegalStateException.class));
        exception.expectCause(hasMessage(is("The given Public Key is null.")));
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        when(provider.getPublicKeyById("my-key-id")).thenReturn(null);
        String jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJhdXRoMCJ9.jXrbue3xJmnzWH9kU-uGeCTtgbQEKbch8uHd4Z52t86ncNyepfusl_bsyLJIcxMwK7odRzKiSE9efV9JaRSEDODDBdMeCzODFx82uBM7e46T1NLVSmjYIM7Hcfh81ZeTIk-hITvgtL6hvTdeJWOCZAB0bs18qSVW5SvursRUhY38xnhuNI6HOHCtqp7etxWAu6670L53I3GtXsmi6bXIzv_0v1xZcAFg4HTvXxfhfj3oCqkSs2nC27mHxBmQtmZKWmXk5HzVUyPRwTUWx5wHPT_hCsGer-CMCAyGsmOg466y1KDqf7ogpMYojfVZGWBsyA39LO1oWZ4Ryomkn8t5Vg";
        Algorithm algorithm = Algorithm.RSA256(provider);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldFailRSA256VerificationWithInvalidPublicKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withRSA");
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA";
        Algorithm algorithm = Algorithm.RSA256((RSAKey) readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE, "RSA"));
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldFailRSA256VerificationWhenUsingPrivateKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withRSA");
        exception.expectCause(isA(IllegalStateException.class));
        exception.expectCause(hasMessage(is("The given Public Key is null.")));
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA";
        Algorithm algorithm = Algorithm.RSA256((RSAKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldPassRSA384Verification() throws Exception {
        String jwt = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw";
        Algorithm algorithm = Algorithm.RSA384((RSAKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"));
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldPassRSA384VerificationWithBothKeys() throws Exception {
        String jwt = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw";
        Algorithm algorithm = Algorithm.RSA384((RSAPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"), (RSAPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldPassRSA384VerificationWithProvidedPublicKey() throws Exception {
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        PublicKey publicKey = readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA");
        when(provider.getPublicKeyById("my-key-id")).thenReturn((RSAPublicKey) publicKey);
        String jwt = "eyJhbGciOiJSUzM4NCIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJhdXRoMCJ9.ITNTVCT7ercumZKHV4-BXGkJwwa7fyF3CnSfEvm09fDFSkaseDxNo_75WLDmK9WM8RMHTPvkpHcTKm4guYEbC_la7RzFIKpU72bppzQojggSmWWXt_6zq50QP2t5HFMebote1zxhp8ccEdSCX5pyY6J2sm9kJ__HKK32KxIVCTjVCz-bFBS60oG35aYEySdKsxuUdWbD5FQ9I16Ony2x0EPvmlL3GPiAPmgjSFp3LtcBIbCDaoonM7iuDRGIQiDN_n2FKKb1Bt4_38uWPtTkwRpNalt6l53Y3JDdzGI5fMrMo3RQnQlAJxUJKD0eL6dRAA645IVIIXucHwuhgGGIVw";
        Algorithm algorithm = Algorithm.RSA384(provider);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldFailRSA384VerificationWhenProvidedPublicKeyIsNull() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withRSA");
        exception.expectCause(isA(IllegalStateException.class));
        exception.expectCause(hasMessage(is("The given Public Key is null.")));
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        when(provider.getPublicKeyById("my-key-id")).thenReturn(null);
        String jwt = "eyJhbGciOiJSUzM4NCIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJhdXRoMCJ9.ITNTVCT7ercumZKHV4-BXGkJwwa7fyF3CnSfEvm09fDFSkaseDxNo_75WLDmK9WM8RMHTPvkpHcTKm4guYEbC_la7RzFIKpU72bppzQojggSmWWXt_6zq50QP2t5HFMebote1zxhp8ccEdSCX5pyY6J2sm9kJ__HKK32KxIVCTjVCz-bFBS60oG35aYEySdKsxuUdWbD5FQ9I16Ony2x0EPvmlL3GPiAPmgjSFp3LtcBIbCDaoonM7iuDRGIQiDN_n2FKKb1Bt4_38uWPtTkwRpNalt6l53Y3JDdzGI5fMrMo3RQnQlAJxUJKD0eL6dRAA645IVIIXucHwuhgGGIVw";
        Algorithm algorithm = Algorithm.RSA384(provider);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldFailRSA384VerificationWithInvalidPublicKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withRSA");
        String jwt = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw";
        Algorithm algorithm = Algorithm.RSA384((RSAKey) readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE, "RSA"));
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldFailRSA384VerificationWhenUsingPrivateKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withRSA");
        exception.expectCause(isA(IllegalStateException.class));
        exception.expectCause(hasMessage(is("The given Public Key is null.")));
        String jwt = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw";
        Algorithm algorithm = Algorithm.RSA384((RSAKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldPassRSA512Verification() throws Exception {
        String jwt = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow";
        Algorithm algorithm = Algorithm.RSA512((RSAKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"));
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldPassRSA512VerificationWithBothKeys() throws Exception {
        String jwt = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow";
        Algorithm algorithm = Algorithm.RSA512((RSAPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"), (RSAPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldPassRSA512VerificationWithProvidedPublicKey() throws Exception {
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        PublicKey publicKey = readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA");
        when(provider.getPublicKeyById("my-key-id")).thenReturn((RSAPublicKey) publicKey);
        String jwt = "eyJhbGciOiJSUzUxMiIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJhdXRoMCJ9.GpHv85Q8tAU_6hNWsmO0GEpO1qz9lmK3NKeAcemysz9MGo4FXWn8xbD8NjCfzZ8EWphm65M0NArKSjpKHO5-gcNsQxLBVfSED1vzcoaZH_Vy5Rp1M76dGH7JghB_66KrpfyMxer_yRJb-KXesNvIroDGilLQF2ENG-IfLF5nBKlDiVHmPaqr3pm1q20fNLhegkSRca4BJ5VdIlT6kOqE_ykVyCBqzD_oXp3LKO_ARnxoeB9SegIW1fy_3tuxSTKYsCZiOfiyVEXXblAuY3pSLZnGvgeBRnfvmWXDWhP0vVUFtYJBF09eULvvUMVqWcrjUG9gDzzzT7veiY_fHd_x8g";
        Algorithm algorithm = Algorithm.RSA512(provider);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldFailRSA512VerificationWhenProvidedPublicKeyIsNull() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withRSA");
        exception.expectCause(isA(IllegalStateException.class));
        exception.expectCause(hasMessage(is("The given Public Key is null.")));
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        when(provider.getPublicKeyById("my-key-id")).thenReturn(null);
        String jwt = "eyJhbGciOiJSUzUxMiIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJhdXRoMCJ9.GpHv85Q8tAU_6hNWsmO0GEpO1qz9lmK3NKeAcemysz9MGo4FXWn8xbD8NjCfzZ8EWphm65M0NArKSjpKHO5-gcNsQxLBVfSED1vzcoaZH_Vy5Rp1M76dGH7JghB_66KrpfyMxer_yRJb-KXesNvIroDGilLQF2ENG-IfLF5nBKlDiVHmPaqr3pm1q20fNLhegkSRca4BJ5VdIlT6kOqE_ykVyCBqzD_oXp3LKO_ARnxoeB9SegIW1fy_3tuxSTKYsCZiOfiyVEXXblAuY3pSLZnGvgeBRnfvmWXDWhP0vVUFtYJBF09eULvvUMVqWcrjUG9gDzzzT7veiY_fHd_x8g";
        Algorithm algorithm = Algorithm.RSA512(provider);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldFailRSA512VerificationWithInvalidPublicKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withRSA");
        String jwt = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow";
        Algorithm algorithm = Algorithm.RSA512((RSAKey) readPublicKeyFromFile(INVALID_PUBLIC_KEY_FILE, "RSA"));
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldFailRSA512VerificationWhenUsingPrivateKey() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withRSA");
        exception.expectCause(isA(IllegalStateException.class));
        exception.expectCause(hasMessage(is("The given Public Key is null.")));
        String jwt = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow";
        Algorithm algorithm = Algorithm.RSA512((RSAKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldThrowWhenMacAlgorithmDoesNotExists() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: some-alg");
        exception.expectCause(isA(NoSuchAlgorithmException.class));
        
        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.verifySignatureFor(anyString(), any(PublicKey.class), any(String.class), any(String.class), any(byte[].class)))
                .thenThrow(NoSuchAlgorithmException.class);

        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        RSAKeyProvider provider = RSAAlgorithm.providerForKeys(publicKey, privateKey);
        Algorithm algorithm = new RSAAlgorithm(crypto, "some-alg", "some-algorithm", provider);
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA";
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldThrowWhenThePublicKeyIsInvalid() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: some-alg");
        exception.expectCause(isA(InvalidKeyException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.verifySignatureFor(anyString(), any(PublicKey.class), any(String.class), any(String.class), any(byte[].class)))
                .thenThrow(InvalidKeyException.class);

        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        RSAKeyProvider provider = RSAAlgorithm.providerForKeys(publicKey, privateKey);
        Algorithm algorithm = new RSAAlgorithm(crypto, "some-alg", "some-algorithm", provider);
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA";
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldThrowWhenTheSignatureIsNotPrepared() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: some-alg");
        exception.expectCause(isA(SignatureException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.verifySignatureFor(anyString(), any(PublicKey.class), any(String.class), any(String.class), any(byte[].class)))
                .thenThrow(SignatureException.class);

        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        RSAKeyProvider provider = RSAAlgorithm.providerForKeys(publicKey, privateKey);
        Algorithm algorithm = new RSAAlgorithm(crypto, "some-alg", "some-algorithm", provider);
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA";
        algorithm.verify(JWT.decode(jwt));
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

        String jwt = asJWT(algorithmSign, RS256Header, auth0IssPayload);
        String expectedSignature = "ZB-Tr0vLtnf8I9fhSdSjU6HZei5xLYZQ6nZqM5O6Va0W9PgAqgRT7ShI9CjeYulRXPHvVmSl5EQuYuXdBzM0-H_3p_Nsl6tSMy4EyX2kkhEm6T0HhvarTh8CG0PCjn5p6FP5ZxWwhLcmRN70ItP6Z5MMO4CcJh1JrNxR4Fi4xQgt-CK2aVDMFXd-Br5yQiLVx1CX83w28OD9wssW3Rdltl5e66vCef0Ql6Q5I5e5F0nqGYT989a9fkNgLIx2F8k_az5x07BY59FV2SZg59nSiY7TZNjP8ot11Ew7HKRfPXOdh9eKRUVdhcxzqDePhyzKabU8TG5FP0SiWH5qVPfAgw";

        assertSignaturePresent(jwt);
        assertSignatureValue(jwt, expectedSignature);
        algorithmVerify.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldDoRSA256SigningWithBothKeys() throws Exception {
        Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"), (RSAPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));

        String jwt = asJWT(algorithm, RS256Header, auth0IssPayload);
        String expectedSignature = "ZB-Tr0vLtnf8I9fhSdSjU6HZei5xLYZQ6nZqM5O6Va0W9PgAqgRT7ShI9CjeYulRXPHvVmSl5EQuYuXdBzM0-H_3p_Nsl6tSMy4EyX2kkhEm6T0HhvarTh8CG0PCjn5p6FP5ZxWwhLcmRN70ItP6Z5MMO4CcJh1JrNxR4Fi4xQgt-CK2aVDMFXd-Br5yQiLVx1CX83w28OD9wssW3Rdltl5e66vCef0Ql6Q5I5e5F0nqGYT989a9fkNgLIx2F8k_az5x07BY59FV2SZg59nSiY7TZNjP8ot11Ew7HKRfPXOdh9eKRUVdhcxzqDePhyzKabU8TG5FP0SiWH5qVPfAgw";

        assertSignaturePresent(jwt);
        assertSignatureValue(jwt, expectedSignature);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldDoRSA256SigningWithProvidedPrivateKey() throws Exception {
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        PrivateKey privateKey = readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA");
        PublicKey publicKey = readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA");
        when(provider.getPrivateKey()).thenReturn((RSAPrivateKey) privateKey);
        when(provider.getPublicKeyById(null)).thenReturn((RSAPublicKey) publicKey);
        Algorithm algorithm = Algorithm.RSA256(provider);
        
        String jwt = asJWT(algorithm, RS256Header, auth0IssPayload);

        assertSignaturePresent(jwt);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldFailOnRSA256SigningWhenProvidedPrivateKeyIsNull() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: SHA256withRSA");
        exception.expectCause(isA(IllegalStateException.class));
        exception.expectCause(hasMessage(is("The given Private Key is null.")));

        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        when(provider.getPrivateKey()).thenReturn(null);
        Algorithm algorithm = Algorithm.RSA256(provider);
        algorithm.sign(new byte[0], new byte[0]);
    }

    @Test
    public void shouldFailOnRSA256SigningWhenUsingPublicKey() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: SHA256withRSA");
        exception.expectCause(isA(IllegalStateException.class));
        exception.expectCause(hasMessage(is("The given Private Key is null.")));

        Algorithm algorithm = Algorithm.RSA256((RSAKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"));
        algorithm.sign(new byte[0], new byte[0]);
    }

    @Test
    public void shouldDoRSA384Signing() throws Exception {
        Algorithm algorithmSign = Algorithm.RSA384((RSAKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));
        Algorithm algorithmVerify = Algorithm.RSA384((RSAKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"));

        String jwt = asJWT(algorithmSign, RS384Header, auth0IssPayload);
        String expectedSignature = "Jx1PaTBnjd_U56MNjifFcY7w9ImDbseg0y8Ijr2pSiA1_wzQb_wy9undaWfzR5YqdIAXvjS8AGuZUAzIoTG4KMgOgdVyYDz3l2jzj6wI-lgqfR5hTy1w1ruMUQ4_wobpdxAiJ4fEbg8Mi_GljOiCO-P1HilxKnpiOJZidR8MQGwTInsf71tOUkK4x5UsdmUueuZbaU-CL5kPnRfXmJj9CcdxZbD9oMlbo23dwkP5BNMrS2LwGGzc9C_-ypxrBIOVilG3WZxcSmuG86LjcZbnL6LBEfph5NmKBgQav147uipb_7umBEr1m2dYiB_9u606n3bcoo3rnsYYK_Xfi1GAEQ";

        assertSignaturePresent(jwt);
        assertSignatureValue(jwt, expectedSignature);
        algorithmVerify.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldDoRSA384SigningWithBothKeys() throws Exception {
        Algorithm algorithm = Algorithm.RSA384((RSAPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"), (RSAPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));

        String jwt = asJWT(algorithm, RS384Header, auth0IssPayload);
        String expectedSignature = "Jx1PaTBnjd_U56MNjifFcY7w9ImDbseg0y8Ijr2pSiA1_wzQb_wy9undaWfzR5YqdIAXvjS8AGuZUAzIoTG4KMgOgdVyYDz3l2jzj6wI-lgqfR5hTy1w1ruMUQ4_wobpdxAiJ4fEbg8Mi_GljOiCO-P1HilxKnpiOJZidR8MQGwTInsf71tOUkK4x5UsdmUueuZbaU-CL5kPnRfXmJj9CcdxZbD9oMlbo23dwkP5BNMrS2LwGGzc9C_-ypxrBIOVilG3WZxcSmuG86LjcZbnL6LBEfph5NmKBgQav147uipb_7umBEr1m2dYiB_9u606n3bcoo3rnsYYK_Xfi1GAEQ";

        assertSignaturePresent(jwt);
        assertSignatureValue(jwt, expectedSignature);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldDoRSA384SigningWithProvidedPrivateKey() throws Exception {
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        PrivateKey privateKey = readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA");
        PublicKey publicKey = readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA");
        when(provider.getPrivateKey()).thenReturn((RSAPrivateKey) privateKey);
        when(provider.getPublicKeyById(null)).thenReturn((RSAPublicKey) publicKey);
        Algorithm algorithm = Algorithm.RSA384(provider);
        
        String jwt = asJWT(algorithm, RS384Header, auth0IssPayload);

        assertSignaturePresent(jwt);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldFailOnRSA384SigningWhenProvidedPrivateKeyIsNull() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: SHA384withRSA");
        exception.expectCause(isA(IllegalStateException.class));
        exception.expectCause(hasMessage(is("The given Private Key is null.")));

        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        when(provider.getPrivateKey()).thenReturn(null);
        Algorithm algorithm = Algorithm.RSA384(provider);
        algorithm.sign(new byte[0], new byte[0]);
    }

    @Test
    public void shouldFailOnRSA384SigningWhenUsingPublicKey() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: SHA384withRSA");
        exception.expectCause(isA(IllegalStateException.class));
        exception.expectCause(hasMessage(is("The given Private Key is null.")));

        Algorithm algorithm = Algorithm.RSA384((RSAKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"));
        algorithm.sign(new byte[0], new byte[0]);
    }

    @Test
    public void shouldDoRSA512Signing() throws Exception {
        Algorithm algorithmSign = Algorithm.RSA512((RSAKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));
        Algorithm algorithmVerify = Algorithm.RSA512((RSAKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"));

        String jwt = asJWT(algorithmSign, RS512Header, auth0IssPayload);
        String expectedSignature = "THIPVYzNZ1Yo_dm0k1UELqV0txs3SzyMopCyHcLXOOdgYXF4MlGvBqu0CFvgSga72Sp5LpuC1Oesj40v_QDsp2GTGDeWnvvcv_eo-b0LPSpmT2h1Ibrmu-z70u2rKf28pkN-AJiMFqi8sit2kMIp1bwIVOovPvMTQKGFmova4Xwb3G526y_PeLlflW1h69hQTIVcI67ACEkAC-byjDnnYIklA-B4GWcggEoFwQRTdRjAUpifA6HOlvnBbZZlUd6KXwEydxVS-eh1odwPjB2_sfbyy5HnLsvNdaniiZQwX7QbwLNT4F72LctYdHHM1QCrID6bgfgYp9Ij9CRX__XDEA";

        assertSignaturePresent(jwt);
        assertSignatureValue(jwt, expectedSignature);
        algorithmVerify.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldDoRSA512SigningWithBothKeys() throws Exception {
        Algorithm algorithm = Algorithm.RSA512((RSAPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"), (RSAPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA"));

        String jwt = asJWT(algorithm, RS512Header, auth0IssPayload);
        String expectedSignature = "THIPVYzNZ1Yo_dm0k1UELqV0txs3SzyMopCyHcLXOOdgYXF4MlGvBqu0CFvgSga72Sp5LpuC1Oesj40v_QDsp2GTGDeWnvvcv_eo-b0LPSpmT2h1Ibrmu-z70u2rKf28pkN-AJiMFqi8sit2kMIp1bwIVOovPvMTQKGFmova4Xwb3G526y_PeLlflW1h69hQTIVcI67ACEkAC-byjDnnYIklA-B4GWcggEoFwQRTdRjAUpifA6HOlvnBbZZlUd6KXwEydxVS-eh1odwPjB2_sfbyy5HnLsvNdaniiZQwX7QbwLNT4F72LctYdHHM1QCrID6bgfgYp9Ij9CRX__XDEA";

        assertSignaturePresent(jwt);
        assertSignatureValue(jwt, expectedSignature);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldDoRSA512SigningWithProvidedPrivateKey() throws Exception {
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        PrivateKey privateKey = readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA");
        PublicKey publicKey = readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA");
        when(provider.getPrivateKey()).thenReturn((RSAPrivateKey) privateKey);
        when(provider.getPublicKeyById(null)).thenReturn((RSAPublicKey) publicKey);
        Algorithm algorithm = Algorithm.RSA512(provider);
        
        String jwt = asJWT(algorithm, RS512Header, auth0IssPayload);

        assertSignaturePresent(jwt);
        algorithm.verify(JWT.decode(jwt));
    }

    @Test
    public void shouldFailOnRSA512SigningWhenProvidedPrivateKeyIsNull() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: SHA512withRSA");
        exception.expectCause(isA(IllegalStateException.class));
        exception.expectCause(hasMessage(is("The given Private Key is null.")));

        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        when(provider.getPrivateKey()).thenReturn(null);
        Algorithm algorithm = Algorithm.RSA512(provider);
        algorithm.sign(new byte[0], new byte[0]);
    }

    @Test
    public void shouldFailOnRSA512SigningWhenUsingPublicKey() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: SHA512withRSA");
        exception.expectCause(isA(IllegalStateException.class));
        exception.expectCause(hasMessage(is("The given Private Key is null.")));

        Algorithm algorithm = Algorithm.RSA512((RSAKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA"));
        algorithm.sign(new byte[0], new byte[0]);
    }

    @Test
    public void shouldThrowOnSignWhenSignatureAlgorithmDoesNotExists() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm");
        exception.expectCause(isA(NoSuchAlgorithmException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.createSignatureFor(anyString(), any(PrivateKey.class), any(byte[].class), any(byte[].class)))
                .thenThrow(NoSuchAlgorithmException.class);

        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        RSAKeyProvider provider = RSAAlgorithm.providerForKeys(publicKey, privateKey);
        Algorithm algorithm = new RSAAlgorithm(crypto, "some-alg", "some-algorithm", provider);
        algorithm.sign(new byte[0], new byte[0]);
    }

    @Test
    public void shouldThrowOnSignWhenThePrivateKeyIsInvalid() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm");
        exception.expectCause(isA(InvalidKeyException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.createSignatureFor(anyString(), any(PrivateKey.class), any(byte[].class), any(byte[].class)))
                .thenThrow(InvalidKeyException.class);

        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        RSAKeyProvider provider = RSAAlgorithm.providerForKeys(publicKey, privateKey);
        Algorithm algorithm = new RSAAlgorithm(crypto, "some-alg", "some-algorithm", provider);
        algorithm.sign(new byte[0], new byte[0]);
    }

    @Test
    public void shouldThrowOnSignWhenTheSignatureIsNotPrepared() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm");
        exception.expectCause(isA(SignatureException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.createSignatureFor(anyString(), any(PrivateKey.class), any(byte[].class), any(byte[].class)))
                .thenThrow(SignatureException.class);

        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        RSAKeyProvider provider = RSAAlgorithm.providerForKeys(publicKey, privateKey);
        Algorithm algorithm = new RSAAlgorithm(crypto, "some-alg", "some-algorithm", provider);
        algorithm.sign(new byte[0], new byte[0]);
    }

    @Test
    public void shouldReturnNullSigningKeyIdIfCreatedWithDefaultProvider() throws Exception {
        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        RSAKeyProvider provider = RSAAlgorithm.providerForKeys(publicKey, privateKey);
        Algorithm algorithm = new RSAAlgorithm("some-alg", "some-algorithm", provider);

        assertThat(algorithm.getSigningKeyId(), is(nullValue()));
    }

    @Test
    public void shouldReturnSigningKeyIdFromProvider() throws Exception {
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        when(provider.getPrivateKeyId()).thenReturn("keyId");
        Algorithm algorithm = new RSAAlgorithm("some-alg", "some-algorithm", provider);

        assertThat(algorithm.getSigningKeyId(), is("keyId"));
    }

    @Test
    public void shouldBeEqualSignatureMethodResults() throws Exception {
        RSAPrivateKey privateKey = (RSAPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE, "RSA");
        RSAPublicKey publicKey = (RSAPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE, "RSA");

        Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);

        byte[] header = new byte[]{0x00, 0x01, 0x02};
        byte[] payload = new byte[]{0x04, 0x05, 0x06};

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        bout.write(header);
        bout.write('.');
        bout.write(payload);

        assertThat(algorithm.sign(bout.toByteArray()), is(algorithm.sign(header, payload)));
    }

}