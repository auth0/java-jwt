package com.auth0.jwtdecodejava;

import com.auth0.jwtdecodejava.algorithms.Algorithm;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.PublicKey;
import java.util.Date;

import static com.auth0.jwtdecodejava.PemUtils.readPublicKeyFromFile;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

public class JWTTest {

    private static final String PUBLIC_KEY_FILE_RSA = "src/test/resources/rsa-public.pem";

    private static final String PUBLIC_KEY_FILE_EC_256 = "src/test/resources/ec256-key-public.pem";
    private static final String PUBLIC_KEY_FILE_EC_384 = "src/test/resources/ec384-key-public.pem";
    private static final String PUBLIC_KEY_FILE_EC_512 = "src/test/resources/ec512-key-public.pem";


    @Rule
    public ExpectedException exception = ExpectedException.none();

    // Initiate with diff Algorithms

    @Test
    public void shouldAcceptNoneAlgorithm() throws Exception {
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
        PublicKey key = readPublicKeyFromFile(PUBLIC_KEY_FILE_RSA, "RSA");
        JWT jwt = JWT.require(Algorithm.RSA256(key))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }


    @Test
    public void shouldAcceptRSA384Algorithm() throws Exception {
        String token = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw";
        PublicKey key = readPublicKeyFromFile(PUBLIC_KEY_FILE_RSA, "RSA");
        JWT jwt = JWT.require(Algorithm.RSA384(key))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldAcceptRSA512Algorithm() throws Exception {
        String token = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow";
        PublicKey key = readPublicKeyFromFile(PUBLIC_KEY_FILE_RSA, "RSA");
        JWT jwt = JWT.require(Algorithm.RSA512(key))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }


    @Test
    public void shouldAcceptECDSA256Algorithm() throws Exception {
        String token = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g";
        PublicKey key = readPublicKeyFromFile(PUBLIC_KEY_FILE_EC_256, "EC");
        JWT jwt = JWT.require(Algorithm.ECDSA256(key))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldAcceptECDSA384Algorithm() throws Exception {
        String token = "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhdXRoMCJ9.50UU5VKNdF1wfykY8jQBKpvuHZoe6IZBJm5NvoB8bR-hnRg6ti-CHbmvoRtlLfnHfwITa_8cJMy6TenMC2g63GQHytc8rYoXqbwtS4R0Ko_AXbLFUmfxnGnMC6v4MS_z";
        PublicKey key = readPublicKeyFromFile(PUBLIC_KEY_FILE_EC_384, "EC");
        JWT jwt = JWT.require(Algorithm.ECDSA384(key))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldAcceptECDSA512Algorithm() throws Exception {
        String token = "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.AeCJPDIsSHhwRSGZCY6rspi8zekOw0K9qYMNridP1Fu9uhrA1QrG-EUxXlE06yvmh2R7Rz0aE7kxBwrnq8L8aOBCAYAsqhzPeUvyp8fXjjgs0Eto5I0mndE2QHlgcMSFASyjHbU8wD2Rq7ZNzGQ5b2MZfpv030WGUajT-aZYWFUJHVg2";
        PublicKey key = readPublicKeyFromFile(PUBLIC_KEY_FILE_EC_512, "EC");
        JWT jwt = JWT.require(Algorithm.ECDSA512(key))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }


    // Public Claims

    @Test
    public void shouldGetAlgorithm() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getAlgorithm(), is("HS256"));
    }

    @Test
    public void shouldGetSignature() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getSignature(), is("XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ"));
    }

    // Public PublicClaims

    @Test
    public void shouldGetIssuer() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJKb2huIERvZSJ9.SgXosfRR_IwCgHq5lF3tlM-JHtpucWCRSaVuoHTbWbQ";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getIssuer(), is("John Doe"));
    }

    @Test
    public void shouldGetSubject() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJUb2szbnMifQ.RudAxkslimoOY3BLl2Ghny3BrUKu9I1ZrXzCZGDJtNs";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getSubject(), is("Tok3ns"));
    }

    @Test
    public void shouldGetArrayAudience() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsiSG9wZSIsIlRyYXZpcyIsIlNvbG9tb24iXX0.Tm4W8WnfPjlmHSmKFakdij0on2rWPETpoM7Sh0u6-S4";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getAudience(), is(arrayWithSize(3)));
        assertThat(jwt.getAudience(), is(arrayContaining("Hope", "Travis", "Solomon")));
    }

    @Test
    public void shouldGetStringAudience() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJKYWNrIFJleWVzIn0.a4I9BBhPt1OB1GW67g2P1bEHgi6zgOjGUL4LvhE9Dgc";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getAudience(), is(arrayWithSize(1)));
        assertThat(jwt.getAudience(), is(arrayContaining("Jack Reyes")));
    }

    @Test
    public void shouldGetExpirationTime() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE0NzY3MjcwODZ9.L9dcPHEDQew2u9MkDCORFkfDGcSOsgoPqNY-LUMLEHg";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getExpiresAt(), is(instanceOf(Date.class)));
        long ms = 1476727086L * 1000;
        Date expectedDate = new Date(ms);
        assertThat(jwt.getExpiresAt(), is(notNullValue()));
        assertThat(jwt.getExpiresAt(), is(equalTo(expectedDate)));
    }

    @Test
    public void shouldGetNotBefore() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYmYiOjE0NzY3MjcwODZ9.tkpD3iCPQPVqjnjpDVp2bJMBAgpVCG9ZjlBuMitass0";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getNotBefore(), is(instanceOf(Date.class)));
        long ms = 1476727086L * 1000;
        Date expectedDate = new Date(ms);
        assertThat(jwt.getNotBefore(), is(notNullValue()));
        assertThat(jwt.getNotBefore(), is(equalTo(expectedDate)));
    }

    @Test
    public void shouldGetIssuedAt() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NzY3MjcwODZ9.KPjGoW665E8V5_27Jugab8qSTxLk2cgquhPCBfAP0_w";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getIssuedAt(), is(instanceOf(Date.class)));
        long ms = 1476727086L * 1000;
        Date expectedDate = new Date(ms);
        assertThat(jwt.getIssuedAt(), is(notNullValue()));
        assertThat(jwt.getIssuedAt(), is(equalTo(expectedDate)));
    }

    @Test
    public void shouldGetId() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIxMjM0NTY3ODkwIn0.m3zgEfVUFOd-CvL3xG5BuOWLzb0zMQZCqiVNQQOPOvA";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getId(), is("1234567890"));
    }

    @Test
    public void shouldGetContentType() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsImN0eSI6ImF3ZXNvbWUifQ.e30.AIm-pJDOaAyct9qKMlN-lQieqNDqc3d4erqUZc5SHAs";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getContentType(), is("awesome"));
    }

    @Test
    public void shouldGetType() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.e30.WdFmrzx8b9v_a-r6EHC2PTAaWywgm_8LiP8RBRhYwkI";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getType(), is("JWS"));
    }
}
