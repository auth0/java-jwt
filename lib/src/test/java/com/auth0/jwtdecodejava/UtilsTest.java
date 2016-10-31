package com.auth0.jwtdecodejava;

import com.auth0.jwtdecodejava.enums.HSAlgorithm;
import com.auth0.jwtdecodejava.enums.RSAlgorithm;
import com.auth0.jwtdecodejava.exceptions.JWTException;
import com.auth0.jwtdecodejava.impl.pem.PemUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.File;
import java.io.IOException;
import java.security.PublicKey;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

public class UtilsTest {

    private static final String PUBLIC_KEY_FILE = "src/test/resources/rsa_public.pem";
    private static final String INVALID_PUBLIC_KEY_FILE = "src/test/resources/rsa_public_invalid.pem";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldSplitToken() throws Exception {
        String token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc";
        String[] parts = Utils.splitToken(token);

        assertThat(parts, is(notNullValue()));
        assertThat(parts, is(arrayWithSize(3)));
        assertThat(parts[0], is("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"));
        assertThat(parts[1], is("eyJpc3MiOiJhdXRoMCJ9"));
        assertThat(parts[2], is("W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc"));
    }

    @Test
    public void shouldSplitTokenWithEmptySignature() throws Exception {
        String token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.";
        String[] parts = Utils.splitToken(token);

        assertThat(parts, is(notNullValue()));
        assertThat(parts, is(arrayWithSize(3)));
        assertThat(parts[0], is("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"));
        assertThat(parts[1], is("eyJpc3MiOiJhdXRoMCJ9"));
        assertThat(parts[2], is(isEmptyString()));
    }

    @Test
    public void shouldThrowOnSplitTokenWithMoreThan3Parts() throws Exception {
        exception.expect(JWTException.class);
        exception.expectMessage("The token was expected to have 3 parts, but got 4.");
        String token = "this.has.four.parts";
        Utils.splitToken(token);
    }

    @Test
    public void shouldThrowOnSplitTokenWithLessThan3Parts() throws Exception {
        exception.expect(JWTException.class);
        exception.expectMessage("The token was expected to have 3 parts, but got 2.");
        String token = "two.parts";
        Utils.splitToken(token);
    }

    @Test
    public void shouldDecodeBase64() throws Exception {
        String source = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        String result = Utils.base64Decode(source);

        assertThat(result, is(notNullValue()));
        assertThat(result, is("{\"alg\":\"HS256\",\"typ\":\"JWT\"}"));
    }

    @Test
    public void shouldEncodeBase64() throws Exception {
        String source = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String result = Utils.base64Encode(source);

        assertThat(result, is(notNullValue()));
        assertThat(result, is("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
    }

    // HS

    @Test
    public void shouldPassHS256Verification() throws Exception {
        String jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        assertTrue(Utils.verifyHS(HSAlgorithm.HS256, jwt.split("\\."), "secret"));
    }

    @Test
    public void shouldFailHS256VerificationWithInvalidSecret() throws Exception {
        String jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        assertFalse(Utils.verifyHS(HSAlgorithm.HS256, jwt.split("\\."), "not_real_secret"));
    }

    @Test
    public void shouldThrowHS256VerificationWithNullSecret() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Secret cannot be null");
        String jwt = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        Utils.verifyHS(HSAlgorithm.HS256, jwt.split("\\."), null);
    }

    @Test
    public void shouldPassHS384Verification() throws Exception {
        String jwt = "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw";
        assertTrue(Utils.verifyHS(HSAlgorithm.HS384, jwt.split("\\."), "secret"));
    }

    @Test
    public void shouldFailHS384VerificationWithInvalidSecret() throws Exception {
        String jwt = "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw";
        assertFalse(Utils.verifyHS(HSAlgorithm.HS384, jwt.split("\\."), "not_real_secret"));
    }

    @Test
    public void shouldThrowHS384VerificationWithNullSecret() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Secret cannot be null");
        String jwt = "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw";
        Utils.verifyHS(HSAlgorithm.HS384, jwt.split("\\."), null);
    }

    @Test
    public void shouldPassHS512Verification() throws Exception {
        String jwt = "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw";
        assertTrue(Utils.verifyHS(HSAlgorithm.HS512, jwt.split("\\."), "secret"));
    }

    @Test
    public void shouldFailHS512VerificationWithInvalidSecret() throws Exception {
        String jwt = "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw";
        assertFalse(Utils.verifyHS(HSAlgorithm.HS512, jwt.split("\\."), "not_real_secret"));
    }

    @Test
    public void shouldThrowHS512VerificationWithNullSecret() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Secret cannot be null");
        String jwt = "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw";
        Utils.verifyHS(HSAlgorithm.HS512, jwt.split("\\."), null);
    }

    @Test
    public void shouldThrowWhenHSAlgorithmIsNull() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Algorithm must be one of HS256, HS384, or HS512.");
        String jwt = "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw";
        Utils.verifyHS(null, jwt.split("\\."), "secret");
    }

    // RS

    @Test
    public void shouldPassRS256Verification() throws Exception {
        PublicKey key = readPublicKey();
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA";
        assertTrue(Utils.verifyRS(RSAlgorithm.RS256, jwt.split("\\."), key));
    }

    @Test
    public void shouldFailRS256VerificationWithInvalidPublicKey() throws Exception {
        PublicKey key = readInvalidPublicKey();
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA";
        assertFalse(Utils.verifyRS(RSAlgorithm.RS256, jwt.split("\\."), key));
    }

    @Test
    public void shouldThrowRS256VerificationWithNullPublicKey() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The PublicKey cannot be null");
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA";
        Utils.verifyRS(RSAlgorithm.RS256, jwt.split("\\."), null);
    }

    @Test
    public void shouldPassRS384Verification() throws Exception {
        PublicKey key = readPublicKey();
        String jwt = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw";
        assertTrue(Utils.verifyRS(RSAlgorithm.RS384, jwt.split("\\."), key));
    }

    @Test
    public void shouldFailRS384VerificationWithInvalidPublicKey() throws Exception {
        PublicKey key = readInvalidPublicKey();
        String jwt = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw";
        assertFalse(Utils.verifyRS(RSAlgorithm.RS384, jwt.split("\\."), key));
    }

    @Test
    public void shouldThrowRS384VerificationWithNullPublicKey() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The PublicKey cannot be null");
        String jwt = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw";
        Utils.verifyRS(RSAlgorithm.RS384, jwt.split("\\."), null);
    }

    @Test
    public void shouldPassRS512Verification() throws Exception {
        PublicKey key = readPublicKey();
        String jwt = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow";
        assertTrue(Utils.verifyRS(RSAlgorithm.RS512, jwt.split("\\."), key));
    }

    @Test
    public void shouldFailRS512VerificationWithInvalidPublicKey() throws Exception {
        PublicKey key = readInvalidPublicKey();
        String jwt = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow";
        assertFalse(Utils.verifyRS(RSAlgorithm.RS512, jwt.split("\\."), key));
    }

    @Test
    public void shouldThrowRS512VerificationWithNullPublicKey() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The PublicKey cannot be null");
        String jwt = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow";
        Utils.verifyRS(RSAlgorithm.RS512, jwt.split("\\."), null);
    }

    @Test
    public void shouldThrowWhenRSAlgorithmIsNull() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Algorithm must be one of RS256, RS384, or RS512.");
        PublicKey key = readPublicKey();
        String jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA";
        Utils.verifyRS(null, jwt.split("\\."), key);
    }

    //Private

    private PublicKey readPublicKey() throws IOException {
        byte[] bytes = PemUtils.parsePEMFile(new File(PUBLIC_KEY_FILE));
        return PemUtils.getPublicKey(bytes, "RSA");
    }

    private PublicKey readInvalidPublicKey() throws IOException {
        byte[] bytes = PemUtils.parsePEMFile(new File(INVALID_PUBLIC_KEY_FILE));
        return PemUtils.getPublicKey(bytes, "RSA");
    }

}