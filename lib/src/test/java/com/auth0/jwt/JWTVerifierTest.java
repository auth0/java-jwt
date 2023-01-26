package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Collections;
import java.util.Date;
import java.util.function.BiPredicate;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;

public class JWTVerifierTest {

    private final Clock mockNow = Clock.fixed(Instant.ofEpochSecond(1477592), ZoneId.of("UTC"));
    private final Clock mockOneSecondEarlier = Clock.offset(mockNow, Duration.ofSeconds(-1));
    private final Clock mockOneSecondLater = Clock.offset(mockNow, Duration.ofSeconds(1));

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldThrowWhenInitializedWithoutAlgorithm() {
        IllegalArgumentException e = assertThrows(null, IllegalArgumentException.class, () ->
                JWTVerifier.init(null));
        assertThat(e.getMessage(), is("The Algorithm cannot be null."));
    }

    @Test
    public void shouldThrowWhenAlgorithmDoesntMatchTheTokensAlgorithm() {
        AlgorithmMismatchException e = assertThrows(null, AlgorithmMismatchException.class, () -> {
            JWTVerifier verifier = JWTVerifier.init(Algorithm.HMAC512("secret")).build();
            verifier.verify("eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.s69x7Mmu4JqwmdxiK6sesALO7tcedbFsKEEITUxw9ho");
        });
        assertThat(e.getMessage(), is("The provided Algorithm doesn't match the one defined in the JWT's Header."));
    }

    @Test
    public void shouldValidateIssuer() {
        String token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withIssuer("auth0")
                .build()
                .verify(token);
        assertThat(jwt, is(notNullValue()));

        //  "iss": ["auth0", "okta"]
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, ()-> {
            String token1 = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withIssuer((String[]) null)
                    .build()
                    .verify(token1);
        });

        assertThat(e.getClaimName(), is("iss"));
    }

    @Test
    public void shouldValidateMultipleIssuers() {
        String auth0Token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        String otherIssuertoken = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJvdGhlcklzc3VlciJ9.k4BCOJJl-c0_Y-49VD_mtt-u0QABKSV5i3W-RKc74co";
        JWTVerifier verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withIssuer("otherIssuer", "auth0")
                .build();

        assertThat(verifier.verify(auth0Token), is(notNullValue()));
        assertThat(verifier.verify(otherIssuertoken), is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidIssuer() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withIssuer("invalid")
                    .build()
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Claim 'iss' value doesn't match the required issuer."));
        assertThat(e.getClaimName(), is(RegisteredClaims.ISSUER));
        assertThat(e.getClaimValue().asString(), is("auth0"));
    }

    @Test
    public void shouldThrowOnNullIssuer() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOm51bGx9.OoiCLipSfflWxkFX2rytvtwEiJ8eAL0opkdXY_ap0qA";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withIssuer("auth0")
                    .build()
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Claim 'iss' value doesn't match the required issuer."));
        assertThat(e.getClaimName(), is(RegisteredClaims.ISSUER));
        assertThat(e.getClaimValue().isNull(), is(true));
    }

    @Test
    public void shouldThrowOnMissingIssuer() {
        MissingClaimException e = assertThrows(null, MissingClaimException.class, () -> {
            String jwt = JWTCreator.init()
                    .sign(Algorithm.HMAC256("secret"));

            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withIssuer("nope")
                    .build()
                    .verify(jwt);
        });
        assertThat(e.getMessage(), is("The Claim 'iss' is not present in the JWT."));
        assertThat(e.getClaimName(), is("iss"));
    }

    @Test
    public void shouldValidateSubject() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withSubject("1234567890")
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidSubject() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withSubject("invalid")
                    .build()
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Claim 'sub' value doesn't match the required one."));
        assertThat(e.getClaimName(), is(RegisteredClaims.SUBJECT));
        assertThat(e.getClaimValue().asString(), is("1234567890"));
    }

    @Test
    public void shouldAcceptAudienceWhenWithAudienceContainsAll() {
        // Token 'aud': ["Mark"]
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJNYXJrIn0.xWB6czYI0XObbVhLAxe55TwChWZg7zO08RxONWU2iY4";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAudience("Mark")
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));

        // Token 'aud': ["Mark", "David"]
        String tokenArr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIl19.6WfbIt8m61f9WlCYIQn5CThvw4UNyC66qrPaoinfssw";
        DecodedJWT jwtArr = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAudience("Mark", "David")
                .build()
                .verify(tokenArr);

        assertThat(jwtArr, is(notNullValue()));
    }

    @Test
    public void shouldAllowWithAnyOfAudienceVerificationToOverrideWithAudience() {
        // Token 'aud' = ["Mark", "David", "John"]
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIiwiSm9obiJdfQ.DX5xXiCaYvr54x_iL0LZsJhK7O6HhAdHeDYkgDeb0Rw";
        Verification verification = JWTVerifier.init(Algorithm.HMAC256("secret")).withAudience("Mark", "Jim");

        Exception exception = null;
        try {
            verification.build().verify(token);
        } catch (Exception e) {
            exception = e;

        }

        assertThat(exception, is(notNullValue()));
        assertThat(exception, is(instanceOf(IncorrectClaimException.class)));
        assertThat(exception.getMessage(), is("The Claim 'aud' value doesn't contain the required audience."));

        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret")).withAnyOfAudience("Mark", "Jim").build().verify(token);
        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldAllowWithAudienceVerificationToOverrideWithAnyOfAudience() {
        // Token 'aud' = ["Mark", "David", "John"]
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIiwiSm9obiJdfQ.DX5xXiCaYvr54x_iL0LZsJhK7O6HhAdHeDYkgDeb0Rw";
        Verification verification = JWTVerifier.init(Algorithm.HMAC256("secret")).withAnyOfAudience("Jim");

        Exception exception = null;
        try {
            verification.build().verify(token);
        } catch (Exception e) {
            exception = e;

        }

        assertThat(exception, is(notNullValue()));
        assertThat(exception, is(instanceOf(IncorrectClaimException.class)));
        assertThat(exception.getMessage(), is("The Claim 'aud' value doesn't contain the required audience."));

        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret")).withAudience("Mark").build().verify(token);
        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldAcceptAudienceWhenWithAudienceAndPartialExpected() {
        // Token 'aud' = ["Mark", "David", "John"]
        String tokenArr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIiwiSm9obiJdfQ.DX5xXiCaYvr54x_iL0LZsJhK7O6HhAdHeDYkgDeb0Rw";
        DecodedJWT jwtArr = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAudience("John")
                .build()
                .verify(tokenArr);

        assertThat(jwtArr, is(notNullValue()));
    }

    @Test
    public void shouldAcceptAudienceWhenAnyOfAudienceAndAllContained() {
        // Token 'aud' = ["Mark", "David", "John"]
        String tokenArr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIiwiSm9obiJdfQ.DX5xXiCaYvr54x_iL0LZsJhK7O6HhAdHeDYkgDeb0Rw";
        DecodedJWT jwtArr = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAnyOfAudience("Mark", "David", "John")
                .build()
                .verify(tokenArr);

        assertThat(jwtArr, is(notNullValue()));
    }

    @Test
    public void shouldThrowWhenAudienceHasNoneOfExpectedAnyOfAudience() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            // Token 'aud' = ["Mark", "David", "John"]
            String tokenArr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIiwiSm9obiJdfQ.DX5xXiCaYvr54x_iL0LZsJhK7O6HhAdHeDYkgDeb0Rw";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withAnyOfAudience("Joe", "Jim")
                    .build()
                    .verify(tokenArr);
        });
        assertThat(e.getMessage(), is("The Claim 'aud' value doesn't contain the required audience."));
        assertThat(e.getClaimName(), is(RegisteredClaims.AUDIENCE));
        assertThat(e.getClaimValue().asArray(String.class), is(new String[] {"Mark","David","John"}));
    }

    @Test
    public void shouldThrowWhenAudienceClaimDoesNotContainAllExpected() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            // Token 'aud' = ["Mark", "David", "John"]
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIiwiSm9obiJdfQ.DX5xXiCaYvr54x_iL0LZsJhK7O6HhAdHeDYkgDeb0Rw";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withAudience("Mark", "Joe")
                    .build()
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Claim 'aud' value doesn't contain the required audience."));
        assertThat(e.getClaimName(), is(RegisteredClaims.AUDIENCE));
        assertThat(e.getClaimValue().asArray(String.class), is(new String[] {"Mark","David","John"}));
    }

    @Test
    public void shouldThrowWhenAudienceClaimIsNull() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            // Token 'aud': null
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpudWxsfQ.bpPyquk3b8KepErKgTidjJ1ZwiOGuoTxam2_x7cElKI";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withAudience("nope")
                    .build()
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Claim 'aud' value doesn't contain the required audience."));
        assertThat(e.getClaimName(), is(RegisteredClaims.AUDIENCE));
        assertThat(e.getClaimValue().isNull(), is(true));
    }

    @Test
    public void shouldThrowWhenAudienceClaimIsMissing(){
        MissingClaimException e = assertThrows(null, MissingClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withAudience("nope")
                    .build()
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Claim 'aud' is not present in the JWT."));
        assertThat(e.getClaimName(), is("aud"));
    }

    @Test
    public void shouldThrowWhenAudienceClaimIsNullWithAnAudience() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            // Token 'aud': [null]
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbbnVsbF19.2cBf7FbkX52h8Vmjnl1DY1PYe_J_YP0KsyeoeYmuca8";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withAnyOfAudience("nope")
                    .build()
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Claim 'aud' value doesn't contain the required audience."));
        assertThat(e.getClaimName(), is(RegisteredClaims.AUDIENCE));
        assertThat(e.getClaimValue().asArray(String.class), is(new String[] {null}));
    }

    @Test
    public void shouldNotReplaceWhenMultipleChecksAreAdded() {
        JWTVerifier verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAudience((String[]) null)
                .withAudience()
                .withAnyOfAudience((String[]) null)
                .withAnyOfAudience()
                .build();

        assertThat(verifier.expectedChecks.size(), is(7)); //3 extra mandatory checks exp, nbf, iat
    }

    @Test
    public void shouldThrowOnNullCustomClaimName() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Custom Claim's name can't be null.");
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim(null, "value");
    }

    @Test
    public void shouldThrowWhenExpectedArrayClaimIsMissing() {
        MissingClaimException e = assertThrows(null, MissingClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhcnJheSI6WzEsMiwzXX0.wKNFBcMdwIpdF9rXRxvexrzSM6umgSFqRO1WZj992YM";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withArrayClaim("missing", 1, 2, 3)
                    .build()
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Claim 'missing' is not present in the JWT."));
        assertThat(e.getClaimName(), is("missing"));
    }

    @Test
    public void shouldThrowWhenExpectedClaimIsMissing() {
        MissingClaimException e = assertThrows(null, MissingClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGFpbSI6InRleHQifQ.aZ27Ze35VvTqxpaSIK5ZcnYHr4SrvANlUbDR8fw9qsQ";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withClaim("missing", "text")
                    .build()
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Claim 'missing' is not present in the JWT."));
        assertThat(e.getClaimName(), is("missing"));
    }

    @Test
    public void shouldThrowOnInvalidCustomClaimValueOfTypeString() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjpbInNvbWV0aGluZyJdfQ.3ENLez6tU_fG0SVFrGmISltZPiXLSHaz_dyn-XFTEGQ";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withClaim("name", "value")
                    .build()
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Claim 'name' value doesn't match the required one."));
        assertThat(e.getClaimName(), is("name"));
        assertThat(e.getClaimValue().asArray(String.class), is(new String[] {"something"}));
    }

    @Test
    public void shouldThrowOnInvalidCustomClaimValueOfTypeInteger() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjpbInNvbWV0aGluZyJdfQ.3ENLez6tU_fG0SVFrGmISltZPiXLSHaz_dyn-XFTEGQ";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withClaim("name", 123)
                    .build()
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Claim 'name' value doesn't match the required one."));
        assertThat(e.getClaimName(), is("name"));
        assertThat(e.getClaimValue().asArray(String.class), is(new String[] {"something"}));
    }

    @Test
    public void shouldThrowOnInvalidCustomClaimValueOfTypeDouble() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjpbInNvbWV0aGluZyJdfQ.3ENLez6tU_fG0SVFrGmISltZPiXLSHaz_dyn-XFTEGQ";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withClaim("name", 23.45)
                    .build()
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Claim 'name' value doesn't match the required one."));
        assertThat(e.getClaimName(), is("name"));
        assertThat(e.getClaimValue().asArray(String.class), is(new String[] {"something"}));
    }

    @Test
    public void shouldThrowOnInvalidCustomClaimValueOfTypeBoolean() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjpbInNvbWV0aGluZyJdfQ.3ENLez6tU_fG0SVFrGmISltZPiXLSHaz_dyn-XFTEGQ";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withClaim("name", true)
                    .build()
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Claim 'name' value doesn't match the required one."));
        assertThat(e.getClaimName(), is("name"));
        assertThat(e.getClaimValue().asArray(String.class), is(new String[] {"something"}));
    }


    @Test
    public void shouldThrowOnInvalidCustomClaimValueOfTypeDate() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjpbInNvbWV0aGluZyJdfQ.3ENLez6tU_fG0SVFrGmISltZPiXLSHaz_dyn-XFTEGQ";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withClaim("name", new Date())
                    .build()
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Claim 'name' value doesn't match the required one."));
        assertThat(e.getClaimName(), is("name"));
        assertThat(e.getClaimValue().asArray(String.class), is(new String[] {"something"}));
    }

    @Test
    public void shouldThrowOnInvalidCustomClaimValue() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjpbInNvbWV0aGluZyJdfQ.3ENLez6tU_fG0SVFrGmISltZPiXLSHaz_dyn-XFTEGQ";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withClaim("name", "check")
                    .build()
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Claim 'name' value doesn't match the required one."));
        assertThat(e.getClaimName(), is("name"));
        assertThat(e.getClaimValue().asArray(String.class), is(new String[] {"something"}));
    }

    @Test
    public void shouldValidateCustomClaimOfTypeString() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidmFsdWUifQ.Jki8pvw6KGbxpMinufrgo6RDL1cu7AtNMJYVh6t-_cE";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", "value")
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateCustomClaimOfTypeInteger() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoxMjN9.XZAudnA7h3_Al5kJydzLjw6RzZC3Q6OvnLEYlhNW7HA";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", 123)
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateCustomClaimOfTypeLong() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjo5MjIzMzcyMDM2ODU0Nzc2MDB9.km-IwQ5IDnTZFmuJzhSgvjTzGkn_Z5X29g4nAuVC56I";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", 922337203685477600L)
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateCustomClaimOfTypeDouble() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoyMy40NX0.7pyX2OmEGaU9q15T8bGFqRm-d3RVTYnqmZNZtxMKSlA";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", 23.45)
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateCustomClaimOfTypeBoolean() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjp0cnVlfQ.FwQ8VfsZNRqBa9PXMinSIQplfLU4-rkCLfIlTLg_MV0";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", true)
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateCustomClaimOfTypeDate() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoxNDc4ODkxNTIxfQ.mhioumeok8fghQEhTKF3QtQAksSvZ_9wIhJmgZLhJ6c";
        Date date = new Date(1478891521123L);
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", date)
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldNotRemoveCustomClaimOfTypeDateWhenNull() {
        JWTVerifier verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", new Date())
                .withClaim("name", (Date) null)
                .build();

        assertThat(verifier.expectedChecks, is(notNullValue()));
        assertThat(verifier.expectedChecks.size(), is(5));
    }

    @Test
    public void shouldValidateCustomArrayClaimOfTypeString() {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbInRleHQiLCIxMjMiLCJ0cnVlIl19.lxM8EcmK1uSZRAPd0HUhXGZJdauRmZmLjoeqz4J9yAA";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withArrayClaim("name", "text", "123", "true")
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateCustomArrayClaimOfTypeInteger() {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbMSwyLDNdfQ.UEuMKRQYrzKAiPpPLhIVawWkKWA1zj0_GderrWUIyFE";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withArrayClaim("name", 1, 2, 3)
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateCustomArrayClaimOfTypeLong() {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbNTAwMDAwMDAwMDAxLDUwMDAwMDAwMDAwMiw1MDAwMDAwMDAwMDNdfQ.vzV7S0gbV9ZAVxChuIt4XZuSVTxMH536rFmoHzxmayM";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withArrayClaim("name", 500000000001L, 500000000002L, 500000000003L)
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateCustomArrayClaimOfTypeLongWhenValueIsInteger() {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbMSwyLDNdfQ.UEuMKRQYrzKAiPpPLhIVawWkKWA1zj0_GderrWUIyFE";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withArrayClaim("name", 1L, 2L, 3L)
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateCustomArrayClaimOfTypeLongWhenValueIsIntegerAndLong() {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbMSw1MDAwMDAwMDAwMDIsNTAwMDAwMDAwMDAzXX0.PQjb2rPPpYjM2sItZEzZcjS2YbfPCp6xksTSPjpjTQA";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withArrayClaim("name", 1L, 500000000002L, 500000000003L)
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    // Generic Delta
    @Test
    public void shouldAddDefaultLeewayToDateClaims() {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(algorithm);
        JWTVerifier verifier = verification
                .build();

        assertThat(verifier.expectedChecks, is(notNullValue()));
        assertThat(verification.getLeewayFor(RegisteredClaims.ISSUED_AT), is(0L));
        assertThat(verification.getLeewayFor(RegisteredClaims.EXPIRES_AT), is(0L));
        assertThat(verification.getLeewayFor(RegisteredClaims.NOT_BEFORE), is(0L));
    }

    @Test
    public void shouldAddCustomLeewayToDateClaims() {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(algorithm);
        JWTVerifier verifier = verification
                .acceptLeeway(1234L)
                .build();

        assertThat(verifier.expectedChecks, is(notNullValue()));
        assertThat(verification.getLeewayFor(RegisteredClaims.ISSUED_AT), is(1234L));
        assertThat(verification.getLeewayFor(RegisteredClaims.EXPIRES_AT), is(1234L));
        assertThat(verification.getLeewayFor(RegisteredClaims.NOT_BEFORE), is(1234L));
    }

    @Test
    public void shouldOverrideDefaultIssuedAtLeeway() {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(algorithm);
        JWTVerifier verifier = verification
                .acceptLeeway(1234L)
                .acceptIssuedAt(9999L)
                .build();

        assertThat(verifier.expectedChecks, is(notNullValue()));
        assertThat(verification.getLeewayFor(RegisteredClaims.ISSUED_AT), is(9999L));
        assertThat(verification.getLeewayFor(RegisteredClaims.EXPIRES_AT), is(1234L));
        assertThat(verification.getLeewayFor(RegisteredClaims.NOT_BEFORE), is(1234L));
    }

    @Test
    public void shouldOverrideDefaultExpiresAtLeeway() {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(algorithm);
        JWTVerifier verifier = verification
                .acceptLeeway(1234L)
                .acceptExpiresAt(9999L)
                .build();

        assertThat(verifier.expectedChecks, is(notNullValue()));
        assertThat(verification.getLeewayFor(RegisteredClaims.ISSUED_AT), is(1234L));
        assertThat(verification.getLeewayFor(RegisteredClaims.EXPIRES_AT), is(9999L));
        assertThat(verification.getLeewayFor(RegisteredClaims.NOT_BEFORE), is(1234L));
    }

    @Test
    public void shouldOverrideDefaultNotBeforeLeeway() {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(algorithm);
        JWTVerifier verifier = verification
                .acceptLeeway(1234L)
                .acceptNotBefore(9999L)
                .build();

        assertThat(verifier.expectedChecks, is(notNullValue()));
        assertThat(verification.getLeewayFor(RegisteredClaims.ISSUED_AT), is(1234L));
        assertThat(verification.getLeewayFor(RegisteredClaims.EXPIRES_AT), is(1234L));
        assertThat(verification.getLeewayFor(RegisteredClaims.NOT_BEFORE), is(9999L));
    }

    @Test
    public void shouldThrowOnNegativeCustomLeeway() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Leeway value can't be negative.");
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier.init(algorithm)
                .acceptLeeway(-1);
    }

    // Expires At

    @Test
    public void shouldValidateExpiresAtWithLeeway() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc1OTJ9.isvT0Pqx0yjnZk53mUFSeYFJLDs-Ls9IsNAm86gIdZo";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"))
                .acceptExpiresAt(2);
        DecodedJWT jwt = verification
                .build(mockOneSecondLater)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateExpiresAtIfPresent() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc1OTJ9.isvT0Pqx0yjnZk53mUFSeYFJLDs-Ls9IsNAm86gIdZo";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"));
        DecodedJWT jwt = verification
                .build(mockOneSecondEarlier)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowWhenExpiresAtIsNow() {
        // exp must be > now
        TokenExpiredException e = assertThrows(null, TokenExpiredException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc1OTJ9.isvT0Pqx0yjnZk53mUFSeYFJLDs-Ls9IsNAm86gIdZo";
            JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"));
            verification
                    .build(mockNow)
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Token has expired on 1970-01-18T02:26:32Z."));
        assertThat(e.getExpiredOn(), is(Instant.ofEpochSecond(1477592L)));
    }

    @Test
    public void shouldThrowOnInvalidExpiresAtIfPresent() {
        TokenExpiredException e = assertThrows(null, TokenExpiredException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc1OTJ9.isvT0Pqx0yjnZk53mUFSeYFJLDs-Ls9IsNAm86gIdZo";
            JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"));
            verification
                    .build(mockOneSecondLater)
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Token has expired on 1970-01-18T02:26:32Z."));
        assertThat(e.getExpiredOn(), is(Instant.ofEpochSecond(1477592L)));
    }

    @Test
    public void shouldThrowOnNegativeExpiresAtLeeway() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Leeway value can't be negative.");
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier.init(algorithm)
                .acceptExpiresAt(-1);
    }

    // Not before
    @Test
    public void shouldValidateNotBeforeWithLeeway() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE0Nzc1OTJ9.wq4ZmnSF2VOxcQBxPLfeh1J2Ozy1Tj5iUaERm3FKaw8";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"))
                .acceptNotBefore(2);
        DecodedJWT jwt = verification
                .build(mockOneSecondEarlier)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidNotBeforeIfPresent() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE0Nzc1OTJ9.wq4ZmnSF2VOxcQBxPLfeh1J2Ozy1Tj5iUaERm3FKaw8";
            JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"));
            verification
                    .build(mockOneSecondEarlier)
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Token can't be used before 1970-01-18T02:26:32Z."));
        assertThat(e.getClaimName(), is(RegisteredClaims.NOT_BEFORE));
        assertThat(e.getClaimValue().asLong(), is(1477592L));
    }

    @Test
    public void shouldValidateNotBeforeIfPresent() {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYmYiOjE0Nzc1OTN9.f4zVV0TbbTG5xxDjSoGZ320JIMchGoQCWrnT5MyQdT0";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"));
        DecodedJWT jwt = verification
                .build(mockOneSecondLater)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldAcceptNotBeforeEqualToNow() {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYmYiOjE0Nzc1OTJ9.71XBtRmkAa4iKnyhbS4NPW-Xr26eAVAdHZgmupS7a5o";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"));
        DecodedJWT jwt = verification
                .build(mockNow)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnNegativeNotBeforeLeeway() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Leeway value can't be negative.");
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier.init(algorithm)
                .acceptNotBefore(-1);
    }

    // Issued At with future date
    @Test
    public void shouldThrowOnFutureIssuedAt() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0Nzc1OTJ9.CWq-6pUXl1bFg81vqOUZbZrheO2kUBd2Xr3FUZmvudE";
            JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"));

            DecodedJWT jwt = verification.build(mockOneSecondEarlier).verify(token);
            assertThat(jwt, is(notNullValue()));
        });
        assertThat(e.getMessage(), is("The Token can't be used before 1970-01-18T02:26:32Z."));
        assertThat(e.getClaimName(), is(RegisteredClaims.ISSUED_AT));
        assertThat(e.getClaimValue().asLong(), is(1477592L));
    }

    // Issued At with future date and ignore flag
    @Test
    public void shouldSkipIssuedAtVerificationWhenFlagIsPassed() {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0Nzc1OTJ9.CWq-6pUXl1bFg81vqOUZbZrheO2kUBd2Xr3FUZmvudE";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"));
        verification.ignoreIssuedAt();

        DecodedJWT jwt = verification.build(mockOneSecondEarlier).verify(token);
        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidIssuedAtIfPresent() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0Nzc1OTJ9.0WJky9eLN7kuxLyZlmbcXRL3Wy8hLoNCEk5CCl2M4lo";
            JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"));
            verification
                    .build(mockOneSecondEarlier)
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Token can't be used before 1970-01-18T02:26:32Z."));
        assertThat(e.getClaimName(), is(RegisteredClaims.ISSUED_AT));
        assertThat(e.getClaimValue().asLong(), is(1477592L));
    }

    @Test
    public void shouldOverrideAcceptIssuedAtWhenIgnoreIssuedAtFlagPassedAndSkipTheVerification() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0Nzc1OTJ9.0WJky9eLN7kuxLyZlmbcXRL3Wy8hLoNCEk5CCl2M4lo";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"))
                .acceptIssuedAt(1)
                .ignoreIssuedAt();
        DecodedJWT jwt = verification
                .build(mockOneSecondEarlier)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateIssuedAtIfPresent() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0Nzc1OTJ9.0WJky9eLN7kuxLyZlmbcXRL3Wy8hLoNCEk5CCl2M4lo";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"));
        DecodedJWT jwt = verification
                .build(mockNow)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnNegativeIssuedAtLeeway() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Leeway value can't be negative.");
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier.init(algorithm)
                .acceptIssuedAt(-1);
    }

    @Test
    public void shouldValidateJWTId() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqd3RfaWRfMTIzIn0.0kegfXUvwOYioP8PDaLMY1IlV8HOAzSVz3EGL7-jWF4";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withJWTId("jwt_id_123")
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidJWTId() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqd3RfaWRfMTIzIn0.0kegfXUvwOYioP8PDaLMY1IlV8HOAzSVz3EGL7-jWF4";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withJWTId("invalid")
                    .build()
                    .verify(token);
        });
        assertThat(e.getMessage(), is("The Claim 'jti' value doesn't match the required one."));
        assertThat(e.getClaimName(), is("jti"));
        assertThat(e.getClaimValue().asString(), is("jwt_id_123"));
    }

    @Test
    public void shouldNotRemoveClaimWhenPassingNull() {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier verifier = JWTVerifier.init(algorithm)
                .withIssuer("iss")
                .withIssuer((String) null)
                .build();

        assertThat(verifier.expectedChecks, is(notNullValue()));
        assertThat(verifier.expectedChecks.size(), is(5));

        verifier = JWTVerifier.init(algorithm)
                .withIssuer("iss")
                .withIssuer((String[]) null)
                .build();

        assertThat(verifier.expectedChecks, is(notNullValue()));
        assertThat(verifier.expectedChecks.size(), is(5));
    }

    @Test
    public void shouldNotRemoveIssuerWhenPassingNullReference() {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier verifier = JWTVerifier.init(algorithm)
                .withIssuer((String) null)
                .build();

        assertThat(verifier.expectedChecks, is(notNullValue()));
        assertThat(verifier.expectedChecks.size(), is(4));

        verifier = JWTVerifier.init(algorithm)
                .withIssuer((String[]) null)
                .build();

        assertThat(verifier.expectedChecks, is(notNullValue()));
        assertThat(verifier.expectedChecks.size(), is(4));

        verifier = JWTVerifier.init(algorithm)
                .withIssuer()
                .build();

        assertThat(verifier.expectedChecks, is(notNullValue()));
        assertThat(verifier.expectedChecks.size(), is(4));

        String emptyIss = "  ";
        verifier = JWTVerifier.init(algorithm)
                .withIssuer(emptyIss)
                .build();

        assertThat(verifier.expectedChecks, is(notNullValue()));
    }

    @Test
    public void shouldSkipClaimValidationsIfNoClaimsRequired() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowWhenVerifyingClaimPresenceButClaimNotPresent() {
        MissingClaimException e = assertThrows(null, MissingClaimException.class, () -> {
            String jwt = JWTCreator.init()
                    .withClaim("custom", "")
                    .sign(Algorithm.HMAC256("secret"));

            JWTVerifier verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withClaimPresence("missing")
                    .build();

            verifier.verify(jwt);
        });
        assertThat(e.getMessage(), is("The Claim 'missing' is not present in the JWT."));
        assertThat(e.getClaimName(), is("missing"));
    }

    @Test
    public void shouldThrowWhenVerifyingClaimPresenceWhenClaimNameIsNull() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Custom Claim's name can't be null.");

        JWTCreator.init()
                .withClaim("custom", "value")
                .sign(Algorithm.HMAC256("secret"));

        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaimPresence(null);
    }

    @Test
    public void shouldVerifyStringClaimPresence() {
        String jwt = JWTCreator.init()
                .withClaim("custom", "")
                .sign(Algorithm.HMAC256("secret"));

        JWTVerifier verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaimPresence("custom")
                .build();

        DecodedJWT decodedJWT = verifier.verify(jwt);
        assertThat(decodedJWT, is(notNullValue()));
    }

    @Test
    public void shouldVerifyBooleanClaimPresence() {
        String jwt = JWTCreator.init()
                .withClaim("custom", true)
                .sign(Algorithm.HMAC256("secret"));

        JWTVerifier verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaimPresence("custom")
                .build();

        DecodedJWT decodedJWT = verifier.verify(jwt);
        assertThat(decodedJWT, is(notNullValue()));
    }

    @Test
    public void shouldVerifyIntegerClaimPresence() {
        String jwt = JWTCreator.init()
                .withClaim("custom", 123)
                .sign(Algorithm.HMAC256("secret"));

        JWTVerifier verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaimPresence("custom")
                .build();

        DecodedJWT decodedJWT = verifier.verify(jwt);
        assertThat(decodedJWT, is(notNullValue()));
    }

    @Test
    public void shouldVerifyLongClaimPresence() {
        String jwt = JWTCreator.init()
                .withClaim("custom", 922337203685477600L)
                .sign(Algorithm.HMAC256("secret"));

        JWTVerifier verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaimPresence("custom")
                .build();

        DecodedJWT decodedJWT = verifier.verify(jwt);
        assertThat(decodedJWT, is(notNullValue()));
    }

    @Test
    public void shouldVerifyDoubleClaimPresence() {
        String jwt = JWTCreator.init()
                .withClaim("custom", 12.34)
                .sign(Algorithm.HMAC256("secret"));

        JWTVerifier verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaimPresence("custom")
                .build();

        DecodedJWT decodedJWT = verifier.verify(jwt);
        assertThat(decodedJWT, is(notNullValue()));
    }

    @Test
    public void shouldVerifyListClaimPresence() {
        String jwt = JWTCreator.init()
                .withClaim("custom", Collections.singletonList("item"))
                .sign(Algorithm.HMAC256("secret"));

        JWTVerifier verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaimPresence("custom")
                .build();

        DecodedJWT decodedJWT = verifier.verify(jwt);
        assertThat(decodedJWT, is(notNullValue()));
    }

    @Test
    public void shouldVerifyMapClaimPresence() {
        String jwt = JWTCreator.init()
                .withClaim("custom", Collections.singletonMap("key", "value"))
                .sign(Algorithm.HMAC256("secret"));

        JWTVerifier verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaimPresence("custom")
                .build();

        DecodedJWT decodedJWT = verifier.verify(jwt);
        assertThat(decodedJWT, is(notNullValue()));
    }

    @Test
    public void shouldVerifyStandardClaimPresence() {
        String jwt = JWTCreator.init()
                .withClaim("aud", "any value")
                .sign(Algorithm.HMAC256("secret"));

        JWTVerifier verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaimPresence("aud")
                .build();

        DecodedJWT decodedJWT = verifier.verify(jwt);
        assertThat(decodedJWT, is(notNullValue()));
    }

    @Test
    public void shouldSuccessfullyVerifyClaimWithPredicate() {
        String jwt = JWTCreator.init()
                .withClaim("claimName", "claimValue")
                .sign(Algorithm.HMAC256("secret"));

        JWTVerifier verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("claimName", (claim, decodedJWT) -> "claimValue".equals(claim.asString()))
                .build();

        DecodedJWT decodedJWT = verifier.verify(jwt);
        assertThat(decodedJWT, is(notNullValue()));
    }

    @Test
    public void shouldThrowWhenPredicateReturnsFalse() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            String jwt = JWTCreator.init()
                    .withClaim("claimName", "claimValue")
                    .sign(Algorithm.HMAC256("secret"));

            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withClaim("claimName", (claim, decodedJWT) -> "nope".equals(claim.asString()))
                    .build()
                    .verify(jwt);
        });
        assertThat(e.getMessage(), is("The Claim 'claimName' value doesn't match the required one."));
        assertThat(e.getClaimName(), is("claimName"));
        assertThat(e.getClaimValue().asString(), is("claimValue"));
    }

    @Test
    public void shouldNotRemovePredicateCheckForNull() {
        JWTVerifier verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("claimName", (claim, decodedJWT) -> "nope".equals(claim.asString()))
                .withClaim("claimName", (BiPredicate<Claim, DecodedJWT>) null)
                .build();

        assertThat(verifier.expectedChecks, is(notNullValue()));
        assertThat(verifier.expectedChecks.size(), is(5));
    }

    @Test
    public void shouldSuccessfullyVerifyClaimWithNull() {
        String jwt = JWTCreator.init()
                .withNullClaim("claimName")
                .sign(Algorithm.HMAC256("secret"));

        JWTVerifier verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withNullClaim("claimName")
                .build();

        DecodedJWT decodedJWT = verifier.verify(jwt);
        assertThat(decodedJWT, is(notNullValue()));
    }

    @Test
    public void shouldThrowWhenNullClaimHasValue() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            String jwt = JWTCreator.init()
                    .withClaim("claimName", "value")
                    .sign(Algorithm.HMAC256("secret"));

            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withNullClaim("claimName")
                    .build()
                    .verify(jwt);
        });
        assertThat(e.getMessage(), is("The Claim 'claimName' value doesn't match the required one."));
        assertThat(e.getClaimName(), is("claimName"));
        assertThat(e.getClaimValue().asString(), is("value"));
    }

    @Test
    public void shouldThrowWhenNullClaimIsMissing() {
        MissingClaimException e = assertThrows(null, MissingClaimException.class, () -> {
            String jwt = JWTCreator.init()
                    .withClaim("claimName", "value")
                    .sign(Algorithm.HMAC256("secret"));

            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withNullClaim("anotherClaimName")
                    .build()
                    .verify(jwt);
        });
        assertThat(e.getMessage(), is("The Claim 'anotherClaimName' is not present in the JWT."));
        assertThat(e.getClaimName(), is("anotherClaimName"));
    }

    @Test
    public void shouldCheckForNullValuesForSubject() {
        // sub = null
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOm51bGx9.y5brmQQ05OYwVvlTg83njUrz6tfpdyWNh17LHU6DxmI";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withSubject(null)
                .build()
                .verify(token);
        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldCheckForNullValuesInIssuer() {
        // iss = null
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOm51bGx9.OoiCLipSfflWxkFX2rytvtwEiJ8eAL0opkdXY_ap0qA";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withIssuer((String) null)
                .withIssuer((String[]) null)
                .withIssuer()
                .build()
                .verify(token);
        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldCheckForNullValuesInJwtId() {
        // jti = null
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOm51bGx9.z_MDyl8uPGH0q0jeB54wbYt3bwKXamU_3MO8LofGvZs";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withJWTId(null)
                .build()
                .verify(token);
        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldCheckForNullValuesInCustomClaims() {
        // jti = null
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjdXN0b20iOm51bGx9.inAuN3Q9UZ6WgbB63O43B1ero2MTqnfzzumr_5qYIls";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("custom", (Boolean) null)
                .withClaim("custom", (Integer) null)
                .withClaim("custom", (Long) null)
                .withClaim("custom", (Double) null)
                .withClaim("custom", (String) null)
                .withClaim("custom", (Date) null)
                .withClaim("custom", (Instant) null)
                .withClaim("custom", (BiPredicate<Claim, DecodedJWT>) null)
                .withArrayClaim("custom", (String[]) null)
                .withArrayClaim("custom", (Integer[]) null)
                .withArrayClaim("custom", (Long[]) null)
                .build()
                .verify(token);
        assertThat(jwt, is(notNullValue()));
    }


    @Test
    public void shouldCheckForNullValuesForAudience() {
        // aud = null
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpudWxsfQ.bpPyquk3b8KepErKgTidjJ1ZwiOGuoTxam2_x7cElKI";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAudience((String[]) null)
                .withAudience((String) null)
                .withAudience()
                .withAnyOfAudience((String[]) null)
                .withAnyOfAudience((String) null)
                .withAnyOfAudience()
                .build()
                .verify(token);
        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldCheckForClaimPresenceEvenForNormalClaimChecks() {
        MissingClaimException e = assertThrows(null, MissingClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpudWxsfQ.bpPyquk3b8KepErKgTidjJ1ZwiOGuoTxam2_x7cElKI";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withClaim("custom", true)
                    .build()
                    .verify(token);
        });
        assertThat(e.getClaimName(), is("custom"));
    }

    @Test
    public void shouldCheckForWrongLongClaim() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjdXN0b20iOjF9.00btiK0sv8pQ2T-hOr9GC5x2osi7--Bsk4pS5cTikqQ";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withClaim("custom", 2L)
                    .build()
                    .verify(token);
        });
        assertThat(e.getClaimName(), is("custom"));
        assertThat(e.getClaimValue().asLong(), is(1L));
    }

    @Test
    public void shouldCheckForWrongLongArrayClaim() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjdXN0b20iOlsxXX0.R9ZSmgtJng062rcEc59u4VKCq89Yk5VlkN9BuMTMvr0";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withArrayClaim("custom", 2L)
                    .build()
                    .verify(token);
        });
        assertThat(e.getClaimName(), is("custom"));
    }

    @Test
    public void shouldCheckForWrongStringArrayClaim() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjdXN0b20iOlsxXX0.R9ZSmgtJng062rcEc59u4VKCq89Yk5VlkN9BuMTMvr0";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withArrayClaim("custom", "2L")
                    .build()
                    .verify(token);
        });
        assertThat(e.getClaimName(), is("custom"));
    }

    @Test
    public void shouldCheckForWrongIntegerArrayClaim() {
        IncorrectClaimException e = assertThrows(null, IncorrectClaimException.class, () -> {
            String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjdXN0b20iOlsxXX0.R9ZSmgtJng062rcEc59u4VKCq89Yk5VlkN9BuMTMvr0";
            JWTVerifier.init(Algorithm.HMAC256("secret"))
                    .withArrayClaim("custom", 2)
                    .build()
                    .verify(token);
        });
        assertThat(e.getClaimName(), is("custom"));
    }
}
