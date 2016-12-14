package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.*;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;

public class JWTCreatorTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldThrowWhenRequestingSignWithoutAlgorithm() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Algorithm cannot be null");
        JWTCreator.init()
                .sign(null);
    }

    @SuppressWarnings("Convert2Diamond")
    @Test
    public void shouldAddHeader() throws Exception {
        Map<String, Object> header = new HashMap<String, Object>();
        header.put("asd", 123);
        String signed = JWTCreator.init()
                .withHeader(header)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[0], is("eyJhbGciOiJIUzI1NiIsImFzZCI6MTIzfQ"));
    }

    @Test
    public void shouldAddIssuer() throws Exception {
        String signed = JWTCreator.init()
                .withIssuer("auth0")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJpc3MiOiJhdXRoMCJ9"));
    }

    @Test
    public void shouldAddSubject() throws Exception {
        String signed = JWTCreator.init()
                .withSubject("1234567890")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJzdWIiOiIxMjM0NTY3ODkwIn0"));
    }

    @Test
    public void shouldAddAudience() throws Exception {
        String signed = JWTCreator.init()
                .withAudience("Mark")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJhdWQiOiJNYXJrIn0"));


        String signedArr = JWTCreator.init()
                .withAudience("Mark", "David")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signedArr, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signedArr)[1], is("eyJhdWQiOlsiTWFyayIsIkRhdmlkIl19"));
    }

    @Test
    public void shouldAddExpiresAt() throws Exception {
        String signed = JWTCreator.init()
                .withExpiresAt(new Date(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJleHAiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddNotBefore() throws Exception {
        String signed = JWTCreator.init()
                .withNotBefore(new Date(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJuYmYiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddIssuedAt() throws Exception {
        String signed = JWTCreator.init()
                .withIssuedAt(new Date(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJpYXQiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddJWTId() throws Exception {
        String signed = JWTCreator.init()
                .withJWTId("jwt_id_123")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJqdGkiOiJqd3RfaWRfMTIzIn0"));
    }

    @Test
    public void shouldRemoveClaimWhenPassingNull() throws Exception {
        String signed = JWTCreator.init()
                .withIssuer("iss")
                .withIssuer(null)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("e30"));
    }

    @Test
    public void shouldSetCorrectAlgorithmInTheHeader() throws Exception {
        String signed = JWTCreator.init()
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[0], is("eyJhbGciOiJIUzI1NiJ9"));
    }

    @Test
    public void shouldSetEmptySignatureIfAlgorithmIsNone() throws Exception {
        String signed = JWTCreator.init()
                .sign(Algorithm.none());
        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[2], is(""));
    }

    @Test
    public void shouldThrowOnNullCustomClaimName() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Custom Claim's name can't be null.");
        JWTCreator.init()
                .withClaim(null, "value");
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeString() throws Exception {
        String jwt = JWTCreator.init()
                .withClaim("name", "value")
                .sign(Algorithm.HMAC256("secret"));
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoidmFsdWUifQ.4qDWJcNQHDVDW1iAcIgZNiu-qqJQ0RIq8X3ETijBx5k";

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt, is(token));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeInteger() throws Exception {
        String jwt = JWTCreator.init()
                .withClaim("name", 123)
                .sign(Algorithm.HMAC256("secret"));
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoxMjN9.5i6ga8YMteicIeZrFZgJyW4OnI_2jpMaUXcDt-_jme4";

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt, is(token));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeDouble() throws Exception {
        String jwt = JWTCreator.init()
                .withClaim("name", 23.45)
                .sign(Algorithm.HMAC256("secret"));
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoyMy40NX0.aFNlMk3WiikukJq1jo4Tf8ztR180wjTfSpqec0xKKqU";

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt, is(token));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeBoolean() throws Exception {
        String jwt = JWTCreator.init()
                .withClaim("name", true)
                .sign(Algorithm.HMAC256("secret"));
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjp0cnVlfQ.jseAYuhVmT1boYrHQfn9wXmomWq_tdGfphLtG_2tj_M";

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt, is(token));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeDate() throws Exception {
        Date date = new Date(1478891521000L);
        String jwt = JWTCreator.init()
                .withClaim("name", date)
                .sign(Algorithm.HMAC256("secret"));
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoxNDc4ODkxNTIxfQ.ZU1B1pDLYoJZhWD8h3_QsK5dViolxvL5Q43Yz9QIxL4";

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt, is(token));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeArray() throws Exception {
        String jwt = JWTCreator.init()
                .withClaim("name", new Object[]{"text", 123, true})
                .sign(Algorithm.HMAC256("secret"));
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbInRleHQiLDEyMyx0cnVlXX0.uSulPFzLSbgfG8Lpr0jq0JDMhDlGGeQrx09PHEymu1E";

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt, is(token));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeList() throws Exception {
        String jwt = JWTCreator.init()
                .withClaim("name", Arrays.asList("text", 123, true))
                .sign(Algorithm.HMAC256("secret"));
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbInRleHQiLDEyMyx0cnVlXX0.uSulPFzLSbgfG8Lpr0jq0JDMhDlGGeQrx09PHEymu1E";

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt, is(token));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeMap() throws Exception {
        String jwt = JWTCreator.init()
                .withClaim("name", Collections.singletonMap("value", new Object[]{"text", 123, true}))
                .sign(Algorithm.HMAC256("secret"));
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjp7InZhbHVlIjpbInRleHQiLDEyMyx0cnVlXX19.CtZqZMoG__8yJQisT__pcv3NlynrkDl6qvq4sERx6D0";

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt, is(token));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeObject() throws Exception {
        String jwt = JWTCreator.init()
                .withClaim("name", new UserPojo("john", 123))
                .sign(Algorithm.HMAC256("secret"));
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjp7Im5hbWUiOiJqb2huIiwiaWQiOjEyM319.4ar5Q2vy8h7mw-FjFp1XRoiiKQrrPqdrSqEfATCGmNM";

        assertThat(jwt, is(notNullValue()));
        assertThat(jwt, is(token));
    }
}