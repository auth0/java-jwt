package com.auth0.jwtdecodejava;

import com.auth0.jwtdecodejava.algorithms.Algorithm;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.PublicKey;

import static com.auth0.jwtdecodejava.PemUtils.readPublicKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;

public class JWTTest {

    private static final String PUBLIC_KEY_FILE = "src/test/resources/rsa_public.pem";

    @Rule
    public ExpectedException exception = ExpectedException.none();


    @Test
    public void shouldAcceptNoneAlgorithmWhenUsingDefaultConstructor() throws Exception {
        String token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.";
        JWT jwt = JWT.require(Algorithm.none())
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldAcceptHMAC256Algorithm() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldAcceptHMAC384Algorithm() throws Exception {
        String token = "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw";
        JWT jwt = JWT.require(Algorithm.HMAC384("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldAcceptHMAC512Algorithm() throws Exception {
        String token = "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw";
        JWT jwt = JWT.require(Algorithm.HMAC512("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }


    @Test
    public void shouldAcceptRSA256Algorithm() throws Exception {
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA";
        PublicKey key = readPublicKey(PUBLIC_KEY_FILE);
        JWT jwt = JWT.require(Algorithm.RSA256(key))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }


    @Test
    public void shouldAcceptRSA384Algorithm() throws Exception {
        String token = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw";
        PublicKey key = readPublicKey(PUBLIC_KEY_FILE);
        JWT jwt = JWT.require(Algorithm.RSA384(key))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldAcceptRSA512Algorithm() throws Exception {
        String token = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow";
        PublicKey key = readPublicKey(PUBLIC_KEY_FILE);
        JWT jwt = JWT.require(Algorithm.RSA512(key))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }


}
