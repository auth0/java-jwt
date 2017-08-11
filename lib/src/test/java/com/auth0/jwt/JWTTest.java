package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Clock;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.codec.binary.Base64;
import org.hamcrest.collection.IsCollectionWithSize;
import org.hamcrest.core.IsCollectionContaining;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Date;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JWTTest {

    private static final String PUBLIC_KEY_FILE_RSA = "src/test/resources/rsa-public.pem";
    private static final String PRIVATE_KEY_FILE_RSA = "src/test/resources/rsa-private.pem";

    private static final String PUBLIC_KEY_FILE_EC_256 = "src/test/resources/ec256-key-public.pem";
    private static final String PUBLIC_KEY_FILE_EC_384 = "src/test/resources/ec384-key-public.pem";
    private static final String PUBLIC_KEY_FILE_EC_512 = "src/test/resources/ec512-key-public.pem";
    private static final String PRIVATE_KEY_FILE_EC_256 = "src/test/resources/ec256-key-private.pem";
    private static final String PRIVATE_KEY_FILE_EC_384 = "src/test/resources/ec384-key-private.pem";
    private static final String PRIVATE_KEY_FILE_EC_512 = "src/test/resources/ec512-key-private.pem";


    @Rule
    public ExpectedException exception = ExpectedException.none();

    // Decode

    @Test
    public void shouldDecodeAStringToken() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        DecodedJWT jwt = JWT.decode(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldDecodeAStringTokenUsingInstance() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        JWT jwt = new JWT();
        DecodedJWT decodedJWT = jwt.decodeJwt(token);

        assertThat(decodedJWT, is(notNullValue()));
    }

    // getToken
    @Test
    public void shouldGetStringToken() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ");
        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getToken(), is(notNullValue()));
        assertThat(jwt.getToken(), is("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ"));
    }

    // getToken
    @Test
    public void shouldGetStringTokenUsingInstance() throws Exception {
        JWT jwt = new JWT();
        DecodedJWT decodedJWT = jwt.decodeJwt("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ");
        assertThat(decodedJWT, is(notNullValue()));
        assertThat(decodedJWT.getToken(), is(notNullValue()));
        assertThat(decodedJWT.getToken(), is("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ"));
    }

    // Verify

    @Test
    public void shouldAcceptNoneAlgorithm() throws Exception {
        String token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.";
        DecodedJWT jwt = JWT.require(Algorithm.none())
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldAcceptHMAC256Algorithm() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        DecodedJWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldAcceptHMAC384Algorithm() throws Exception {
        String token = "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw";
        DecodedJWT jwt = JWT.require(Algorithm.HMAC384("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldAcceptHMAC512Algorithm() throws Exception {
        String token = "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw";
        DecodedJWT jwt = JWT.require(Algorithm.HMAC512("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }


    @Test
    public void shouldAcceptRSA256Algorithm() throws Exception {
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.dxXF3MdsyW-AuvwJpaQtrZ33fAde9xWxpLIg9cO2tMLH2GSRNuLAe61KsJusZhqZB9Iy7DvflcmRz-9OZndm6cj_ThGeJH2LLc90K83UEvvRPo8l85RrQb8PcanxCgIs2RcZOLygERizB3pr5icGkzR7R2y6zgNCjKJ5_NJ6EiZsGN6_nc2PRK_DbyY-Wn0QDxIxKoA5YgQJ9qafe7IN980pXvQv2Z62c3XR8dYuaXBqhthBj-AbaFHEpZapN-V-TmuLNzR2MCB6Xr7BYMuCaqWf_XU8og4XNe8f_8w9Wv5vvgqMM1KhqVpG5VdMJv4o_L4NoCROHhtUQSLRh2M9cA";
        RSAKey key = (RSAKey) PemUtils.readPublicKeyFromFile(PUBLIC_KEY_FILE_RSA, "RSA");
        DecodedJWT jwt = JWT.require(Algorithm.RSA256(key))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }


    @Test
    public void shouldAcceptRSA384Algorithm() throws Exception {
        String token = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.TZlWjXObwGSQOiu2oMq8kiKz0_BR7bbBddNL6G8eZ_GoR82BXOZDqNrQr7lb_M-78XGBguWLWNIdYhzgxOUL9EoCJlrqVm9s9vo6G8T1sj1op-4TbjXZ61TwIvrJee9BvPLdKUJ9_fp1Js5kl6yXkst40Th8Auc5as4n49MLkipjpEhKDKaENKHpSubs1ripSz8SCQZSofeTM_EWVwSw7cpiM8Fy8jOPvWG8Xz4-e3ODFowvHVsDcONX_4FTMNbeRqDuHq2ZhCJnEfzcSJdrve_5VD5fM1LperBVslTrOxIgClOJ3RmM7-WnaizJrWP3D6Z9OLxPxLhM6-jx6tcxEw";
        RSAKey key = (RSAKey) PemUtils.readPublicKeyFromFile(PUBLIC_KEY_FILE_RSA, "RSA");
        DecodedJWT jwt = JWT.require(Algorithm.RSA384(key))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldAcceptRSA512Algorithm() throws Exception {
        String token = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mvL5LoMyIrWYjk5umEXZTmbyIrkbbcVPUkvdGZbu0qFBxGOf0nXP5PZBvPcOu084lvpwVox5n3VaD4iqzW-PsJyvKFgi5TnwmsbKchAp7JexQEsQOnTSGcfRqeUUiBZqRQdYsho71oAB3T4FnalDdFEpM-fztcZY9XqKyayqZLreTeBjqJm4jfOWH7KfGBHgZExQhe96NLq1UA9eUyQwdOA1Z0SgXe4Ja5PxZ6Fm37KnVDtDlNnY4JAAGFo6y74aGNnp_BKgpaVJCGFu1f1S5xCQ1HSvs8ZSdVWs5NgawW3wRd0kRt_GJ_Y3mIwiF4qUyHWGtsSHu_qjVdCTtbFyow";
        RSAKey key = (RSAKey) PemUtils.readPublicKeyFromFile(PUBLIC_KEY_FILE_RSA, "RSA");
        DecodedJWT jwt = JWT.require(Algorithm.RSA512(key))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }


    @Test
    public void shouldAcceptECDSA256Algorithm() throws Exception {
        String token = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g";
        ECKey key = (ECKey) PemUtils.readPublicKeyFromFile(PUBLIC_KEY_FILE_EC_256, "EC");
        DecodedJWT jwt = JWT.require(Algorithm.ECDSA256(key))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldAcceptECDSA384Algorithm() throws Exception {
        String token = "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhdXRoMCJ9.50UU5VKNdF1wfykY8jQBKpvuHZoe6IZBJm5NvoB8bR-hnRg6ti-CHbmvoRtlLfnHfwITa_8cJMy6TenMC2g63GQHytc8rYoXqbwtS4R0Ko_AXbLFUmfxnGnMC6v4MS_z";
        ECKey key = (ECKey) PemUtils.readPublicKeyFromFile(PUBLIC_KEY_FILE_EC_384, "EC");
        DecodedJWT jwt = JWT.require(Algorithm.ECDSA384(key))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldAcceptECDSA512Algorithm() throws Exception {
        String token = "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.AeCJPDIsSHhwRSGZCY6rspi8zekOw0K9qYMNridP1Fu9uhrA1QrG-EUxXlE06yvmh2R7Rz0aE7kxBwrnq8L8aOBCAYAsqhzPeUvyp8fXjjgs0Eto5I0mndE2QHlgcMSFASyjHbU8wD2Rq7ZNzGQ5b2MZfpv030WGUajT-aZYWFUJHVg2";
        ECKey key = (ECKey) PemUtils.readPublicKeyFromFile(PUBLIC_KEY_FILE_EC_512, "EC");
        DecodedJWT jwt = JWT.require(Algorithm.ECDSA512(key))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }


    // Public Claims

    @Test
    public void shouldGetAlgorithm() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ";
        DecodedJWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getAlgorithm(), is("HS256"));
    }

    @Test
    public void shouldGetSignature() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ";
        DecodedJWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getSignature(), is("XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ"));
    }

    @Test
    public void shouldGetIssuer() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJKb2huIERvZSJ9.SgXosfRR_IwCgHq5lF3tlM-JHtpucWCRSaVuoHTbWbQ";
        DecodedJWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getIssuer(), is("John Doe"));
    }

    @Test
    public void shouldGetSubject() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJUb2szbnMifQ.RudAxkslimoOY3BLl2Ghny3BrUKu9I1ZrXzCZGDJtNs";
        DecodedJWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getSubject(), is("Tok3ns"));
    }

    @Test
    public void shouldGetArrayAudience() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsiSG9wZSIsIlRyYXZpcyIsIlNvbG9tb24iXX0.Tm4W8WnfPjlmHSmKFakdij0on2rWPETpoM7Sh0u6-S4";
        DecodedJWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getAudience(), is(IsCollectionWithSize.hasSize(3)));
        assertThat(jwt.getAudience(), is(IsCollectionContaining.hasItems("Hope", "Travis", "Solomon")));
    }

    @Test
    public void shouldGetStringAudience() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJKYWNrIFJleWVzIn0.a4I9BBhPt1OB1GW67g2P1bEHgi6zgOjGUL4LvhE9Dgc";
        DecodedJWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getAudience(), is(IsCollectionWithSize.hasSize(1)));
        assertThat(jwt.getAudience(), is(IsCollectionContaining.hasItems("Jack Reyes")));
    }

    @Test
    public void shouldGetExpirationTime() throws Exception {
        Date expectedDate = new Date(1477592 * 1000);
        Clock clock = mock(Clock.class);
        when(clock.getToday()).thenReturn(expectedDate);

        String token = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE0Nzc1OTJ9.x_ZjkPkKYUV5tdvc0l8go6D_z2kez1MQcOxokXrDc3k";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWT.require(Algorithm.HMAC256("secret"));
        DecodedJWT jwt = verification
                .build(clock)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getExpiresAt(), is(instanceOf(Date.class)));
        assertThat(jwt.getExpiresAt(), is(notNullValue()));
        assertThat(jwt.getExpiresAt(), is(equalTo(expectedDate)));
    }

    @Test
    public void shouldGetNotBefore() throws Exception {
        Date expectedDate = new Date(1477592 * 1000);
        Clock clock = mock(Clock.class);
        when(clock.getToday()).thenReturn(expectedDate);

        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYmYiOjE0Nzc1OTJ9.mWYSOPoNXstjKbZkKrqgkwPOQWEx3F3gMm6PMcfuJd8";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWT.require(Algorithm.HMAC256("secret"));
        DecodedJWT jwt = verification
                .build(clock)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getNotBefore(), is(instanceOf(Date.class)));
        assertThat(jwt.getNotBefore(), is(notNullValue()));
        assertThat(jwt.getNotBefore(), is(equalTo(expectedDate)));
    }

    @Test
    public void shouldGetIssuedAt() throws Exception {
        Date expectedDate = new Date(1477592 * 1000);
        Clock clock = mock(Clock.class);
        when(clock.getToday()).thenReturn(expectedDate);

        String token = "eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0Nzc1OTJ9.5o1CKlLFjKKcddZzoarQ37pq7qZqNPav3sdZ_bsZaD4";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWT.require(Algorithm.HMAC256("secret"));
        DecodedJWT jwt = verification
                .build(clock)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getIssuedAt(), is(instanceOf(Date.class)));
        assertThat(jwt.getIssuedAt(), is(notNullValue()));
        assertThat(jwt.getIssuedAt(), is(equalTo(expectedDate)));
    }

    @Test
    public void shouldGetId() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIxMjM0NTY3ODkwIn0.m3zgEfVUFOd-CvL3xG5BuOWLzb0zMQZCqiVNQQOPOvA";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWT.require(Algorithm.HMAC256("secret"));
        DecodedJWT jwt = verification
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getId(), is("1234567890"));
    }

    @Test
    public void shouldGetContentType() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsImN0eSI6ImF3ZXNvbWUifQ.e30.AIm-pJDOaAyct9qKMlN-lQieqNDqc3d4erqUZc5SHAs";
        DecodedJWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getContentType(), is("awesome"));
    }

    @Test
    public void shouldGetType() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.e30.WdFmrzx8b9v_a-r6EHC2PTAaWywgm_8LiP8RBRhYwkI";
        DecodedJWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getType(), is("JWS"));
    }

    @Test
    public void shouldGetKeyId() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleSJ9.e30.von1Vt9tq9cn5ZYdX1f4cf2EE7fUvb5BCBlKOTm9YWs";
        DecodedJWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getKeyId(), is("key"));
    }

    @Test
    public void shouldGetCustomClaims() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsImlzQWRtaW4iOnRydWV9.eyJpc0FkbWluIjoibm9wZSJ9.YDKBAgUDbh0PkhioDcLNzdQ8c2Gdf_yS6zdEtJQS3F0";
        DecodedJWT jwt = JWT.require(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt.getHeaderClaim("isAdmin"), notNullValue());
        assertThat(jwt.getHeaderClaim("isAdmin").asBoolean(), is(true));
        assertThat(jwt.getClaim("isAdmin"), notNullValue());
        assertThat(jwt.getClaim("isAdmin").asString(), is("nope"));
    }

    // Sign

    @Test
    public void shouldCreateAnEmptyHMAC256SignedToken() throws Exception {
        String signed = JWT.create().sign(Algorithm.HMAC256("secret"));
        assertThat(signed, is(notNullValue()));

        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("alg", "HS256"));
        assertThat(headerJson, JsonMatcher.hasEntry("typ", "JWT"));
        assertThat(parts[1], is("e30"));

        JWTVerifier verified = JWT.require(Algorithm.HMAC256("secret"))
                .build();
        assertThat(verified, is(notNullValue()));
    }

    @Test
    public void shouldCreateAnEmptyHMAC384SignedToken() throws Exception {
        String signed = JWT.create().sign(Algorithm.HMAC384("secret"));
        assertThat(signed, is(notNullValue()));

        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("alg", "HS384"));
        assertThat(headerJson, JsonMatcher.hasEntry("typ", "JWT"));
        assertThat(parts[1], is("e30"));

        JWTVerifier verified = JWT.require(Algorithm.HMAC384("secret"))
                .build();
        assertThat(verified, is(notNullValue()));
    }

    @Test
    public void shouldCreateAnEmptyHMAC512SignedToken() throws Exception {
        String signed = JWT.create().sign(Algorithm.HMAC512("secret"));
        assertThat(signed, is(notNullValue()));

        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("alg", "HS512"));
        assertThat(headerJson, JsonMatcher.hasEntry("typ", "JWT"));
        assertThat(parts[1], is("e30"));

        JWTVerifier verified = JWT.require(Algorithm.HMAC512("secret"))
                .build();
        assertThat(verified, is(notNullValue()));
    }

    @Test
    public void shouldCreateAnEmptyRSA256SignedToken() throws Exception {
        String signed = JWT.create().sign(Algorithm.RSA256((RSAKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_RSA, "RSA")));
        assertThat(signed, is(notNullValue()));

        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("alg", "RS256"));
        assertThat(headerJson, JsonMatcher.hasEntry("typ", "JWT"));
        assertThat(parts[1], is("e30"));

        JWTVerifier verified = JWT.require(Algorithm.RSA256((RSAKey) PemUtils.readPublicKeyFromFile(PUBLIC_KEY_FILE_RSA, "RSA")))
                .build();
        assertThat(verified, is(notNullValue()));
    }

    @Test
    public void shouldCreateAnEmptyRSA384SignedToken() throws Exception {
        String signed = JWT.create().sign(Algorithm.RSA384((RSAKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_RSA, "RSA")));
        assertThat(signed, is(notNullValue()));

        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("alg", "RS384"));
        assertThat(headerJson, JsonMatcher.hasEntry("typ", "JWT"));
        assertThat(parts[1], is("e30"));

        JWTVerifier verified = JWT.require(Algorithm.RSA384((RSAKey) PemUtils.readPublicKeyFromFile(PUBLIC_KEY_FILE_RSA, "RSA")))
                .build();
        assertThat(verified, is(notNullValue()));
    }

    @Test
    public void shouldCreateAnEmptyRSA512SignedToken() throws Exception {
        String signed = JWT.create().sign(Algorithm.RSA512((RSAKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_RSA, "RSA")));
        assertThat(signed, is(notNullValue()));

        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("alg", "RS512"));
        assertThat(headerJson, JsonMatcher.hasEntry("typ", "JWT"));
        assertThat(parts[1], is("e30"));

        JWTVerifier verified = JWT.require(Algorithm.RSA512((RSAKey) PemUtils.readPublicKeyFromFile(PUBLIC_KEY_FILE_RSA, "RSA")))
                .build();
        assertThat(verified, is(notNullValue()));
    }

    @Test
    public void shouldCreateAnEmptyECDSA256SignedToken() throws Exception {
        String signed = JWT.create().sign(Algorithm.ECDSA256((ECKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_EC_256, "EC")));
        assertThat(signed, is(notNullValue()));

        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("alg", "ES256"));
        assertThat(headerJson, JsonMatcher.hasEntry("typ", "JWT"));
        assertThat(parts[1], is("e30"));

        JWTVerifier verified = JWT.require(Algorithm.ECDSA256((ECKey) PemUtils.readPublicKeyFromFile(PUBLIC_KEY_FILE_EC_256, "EC")))
                .build();
        assertThat(verified, is(notNullValue()));
    }

    @Test
    public void shouldCreateAnEmptyECDSA384SignedToken() throws Exception {
        String signed = JWT.create().sign(Algorithm.ECDSA384((ECKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_EC_384, "EC")));
        assertThat(signed, is(notNullValue()));

        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("alg", "ES384"));
        assertThat(headerJson, JsonMatcher.hasEntry("typ", "JWT"));
        assertThat(parts[1], is("e30"));

        JWTVerifier verified = JWT.require(Algorithm.ECDSA384((ECKey) PemUtils.readPublicKeyFromFile(PUBLIC_KEY_FILE_EC_384, "EC")))
                .build();
        assertThat(verified, is(notNullValue()));
    }

    @Test
    public void shouldCreateAnEmptyECDSA512SignedToken() throws Exception {
        String signed = JWT.create().sign(Algorithm.ECDSA512((ECKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_EC_512, "EC")));
        assertThat(signed, is(notNullValue()));

        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("alg", "ES512"));
        assertThat(headerJson, JsonMatcher.hasEntry("typ", "JWT"));
        assertThat(parts[1], is("e30"));

        JWTVerifier verified = JWT.require(Algorithm.ECDSA512((ECKey) PemUtils.readPublicKeyFromFile(PUBLIC_KEY_FILE_EC_512, "EC")))
                .build();
        assertThat(verified, is(notNullValue()));
    }
}
