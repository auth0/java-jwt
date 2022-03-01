package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.TokenExpiredException;
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
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.startsWith;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.*;

public class JWTVerifierTest {

    private Clock mockNow = Clock.fixed(Instant.ofEpochSecond(1477592), ZoneId.of("UTC"));
    private Clock mockOneSecondEarlier = Clock.offset(mockNow, Duration.ofSeconds(-1));
    private Clock mockOneSecondLater = Clock.offset(mockNow, Duration.ofSeconds(1));

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldThrowWhenInitializedWithoutAlgorithm() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Algorithm cannot be null");
        JWTVerifier.init(null);
    }

    @Test
    public void shouldThrowWhenAlgorithmDoesntMatchTheTokensAlgorithm() throws Exception {
        exception.expect(AlgorithmMismatchException.class);
        exception.expectMessage("The provided Algorithm doesn't match the one defined in the JWT's Header.");
        JWTVerifier verifier = JWTVerifier.init(Algorithm.HMAC512("secret")).build();
        verifier.verify("eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.s69x7Mmu4JqwmdxiK6sesALO7tcedbFsKEEITUxw9ho");
    }

    @Test
    public void shouldValidateIssuer() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withIssuer("auth0")
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
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
    public void shouldThrowOnInvalidIssuer() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'iss' value doesn't match the required issuer.");
        String token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withIssuer("invalid")
                .build()
                .verify(token);
    }

    @Test
    public void shouldThrowOnNullIssuer() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'iss' value doesn't match the required issuer.");

        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withIssuer("auth0")
                .build()
                .verify(token);
    }

    @Test
    public void shouldValidateSubject() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withSubject("1234567890")
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidSubject() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'sub' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withSubject("invalid")
                .build()
                .verify(token);
    }

    @Test
    public void shouldAcceptAudienceWhenWithAudienceContainsAll() throws Exception {
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
        assertThat(exception, is(instanceOf(InvalidClaimException.class)));
        assertThat(exception.getMessage(), is("The Claim 'aud' value doesn't contain the required audience."));

        DecodedJWT jwt = verification.withAnyOfAudience("Mark", "Jim").build().verify(token);
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
        assertThat(exception, is(instanceOf(InvalidClaimException.class)));
        assertThat(exception.getMessage(), is("The Claim 'aud' value doesn't contain the required audience."));

        DecodedJWT jwt = verification.withAudience("Mark").build().verify(token);
        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldAcceptAudienceWhenWithAudienceAndPartialExpected() throws Exception {
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
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'aud' value doesn't contain the required audience.");

        // Token 'aud' = ["Mark", "David", "John"]
        String tokenArr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIiwiSm9obiJdfQ.DX5xXiCaYvr54x_iL0LZsJhK7O6HhAdHeDYkgDeb0Rw";
        DecodedJWT jwtArr = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAnyOfAudience("Joe", "Jim")
                .build()
                .verify(tokenArr);
    }

    @Test
    public void shouldThrowWhenAudienceClaimDoesNotContainAllExpected() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'aud' value doesn't contain the required audience.");

        // Token 'aud' = ["Mark", "David", "John"]
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIiwiSm9obiJdfQ.DX5xXiCaYvr54x_iL0LZsJhK7O6HhAdHeDYkgDeb0Rw";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAudience("Mark", "Joe")
                .build()
                .verify(token);
    }

    @Test
    public void shouldThrowWhenAudienceClaimIsNull() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'aud' value doesn't contain the required audience.");

        // Token 'aud': null
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAudience("nope")
                .build()
                .verify(token);
    }

    @Test
    public void shouldThrowWhenAudienceClaimIsNullWithAnAudience() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'aud' value doesn't contain the required audience.");

        // Token 'aud': null
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withAnyOfAudience("nope")
                .build()
                .verify(token);
    }

    @Test
    public void shouldRemoveAudienceWhenPassingNullReference() throws Exception {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier verifier = JWTVerifier.init(algorithm)
                .withAudience((String) null)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, not(hasKey(JWTVerifier.AUDIENCE_EXACT)));

        verifier = JWTVerifier.init(algorithm)
                .withAudience((String[]) null)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, not(hasKey(JWTVerifier.AUDIENCE_EXACT)));

        verifier = JWTVerifier.init(algorithm)
                .withAudience()
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, not(hasKey(JWTVerifier.AUDIENCE_EXACT)));

        String emptyAud = "   ";
        verifier = JWTVerifier.init(algorithm)
                .withAudience(emptyAud)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, hasEntry(JWTVerifier.AUDIENCE_EXACT, Collections.singletonList(emptyAud)));
    }

    @Test
    public void shouldRemoveAudienceWhenPassingNullReferenceWithAnyOfAudience() throws Exception {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier verifier = JWTVerifier.init(algorithm)
                .withAnyOfAudience((String) null)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, not(hasKey(JWTVerifier.AUDIENCE_CONTAINS)));

        verifier = JWTVerifier.init(algorithm)
                .withAnyOfAudience((String[]) null)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, not(hasKey(JWTVerifier.AUDIENCE_CONTAINS)));

        verifier = JWTVerifier.init(algorithm)
                .withAnyOfAudience()
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, not(hasKey(JWTVerifier.AUDIENCE_CONTAINS)));

        String emptyAud = "   ";
        verifier = JWTVerifier.init(algorithm)
                .withAnyOfAudience(emptyAud)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, hasEntry(JWTVerifier.AUDIENCE_CONTAINS, Collections.singletonList(emptyAud)));
    }

    @Test
    public void shouldRemoveAudienceWhenPassingNull() throws Exception {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier verifier = JWTVerifier.init(algorithm)
                .withAudience("John")
                .withAudience((String) null)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, not(hasKey("aud")));

        verifier = JWTVerifier.init(algorithm)
                .withAudience("John")
                .withAudience((String[]) null)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, not(hasKey("aud")));
    }

    @Test
    public void shouldRemoveAudienceWhenPassingNullWithAnyAudience() throws Exception {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier verifier = JWTVerifier.init(algorithm)
                .withAnyOfAudience("John")
                .withAnyOfAudience((String) null)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, not(hasKey("aud")));

        verifier = JWTVerifier.init(algorithm)
                .withAnyOfAudience("John")
                .withAnyOfAudience((String[]) null)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, not(hasKey("aud")));
    }

    @Test
    public void shouldThrowOnNullCustomClaimName() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Custom Claim's name can't be null.");
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim(null, "value");
    }

    @Test
    public void shouldThrowWhenExpectedArrayClaimIsMissing() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'missing' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhcnJheSI6WzEsMiwzXX0.wKNFBcMdwIpdF9rXRxvexrzSM6umgSFqRO1WZj992YM";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withArrayClaim("missing", 1, 2, 3)
                .build()
                .verify(token);
    }

    @Test
    public void shouldThrowWhenExpectedClaimIsMissing() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'missing' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGFpbSI6InRleHQifQ.aZ27Ze35VvTqxpaSIK5ZcnYHr4SrvANlUbDR8fw9qsQ";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("missing", "text")
                .build()
                .verify(token);
    }

    @Test
    public void shouldThrowOnInvalidCustomClaimValueOfTypeString() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'name' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjpbInNvbWV0aGluZyJdfQ.3ENLez6tU_fG0SVFrGmISltZPiXLSHaz_dyn-XFTEGQ";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", "value")
                .build()
                .verify(token);
    }

    @Test
    public void shouldThrowOnInvalidCustomClaimValueOfTypeInteger() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'name' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjpbInNvbWV0aGluZyJdfQ.3ENLez6tU_fG0SVFrGmISltZPiXLSHaz_dyn-XFTEGQ";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", 123)
                .build()
                .verify(token);
    }

    @Test
    public void shouldThrowOnInvalidCustomClaimValueOfTypeDouble() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'name' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjpbInNvbWV0aGluZyJdfQ.3ENLez6tU_fG0SVFrGmISltZPiXLSHaz_dyn-XFTEGQ";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", 23.45)
                .build()
                .verify(token);
    }

    @Test
    public void shouldThrowOnInvalidCustomClaimValueOfTypeBoolean() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'name' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjpbInNvbWV0aGluZyJdfQ.3ENLez6tU_fG0SVFrGmISltZPiXLSHaz_dyn-XFTEGQ";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", true)
                .build()
                .verify(token);
    }


    @Test
    public void shouldThrowOnInvalidCustomClaimValueOfTypeDate() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'name' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjpbInNvbWV0aGluZyJdfQ.3ENLez6tU_fG0SVFrGmISltZPiXLSHaz_dyn-XFTEGQ";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", new Date())
                .build()
                .verify(token);
    }

    @Test
    public void shouldThrowOnInvalidCustomClaimValue() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'name' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjpbInNvbWV0aGluZyJdfQ.3ENLez6tU_fG0SVFrGmISltZPiXLSHaz_dyn-XFTEGQ";
        Map<String, Object> map = new HashMap<>();
        map.put("name", new Object());
        JWTVerifier verifier = new JWTVerifier(Algorithm.HMAC256("secret"), map, Clock.systemUTC());
        verifier.verify(token);
    }

    @Test
    public void shouldValidateCustomClaimOfTypeString() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidmFsdWUifQ.Jki8pvw6KGbxpMinufrgo6RDL1cu7AtNMJYVh6t-_cE";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", "value")
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateCustomClaimOfTypeInteger() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoxMjN9.XZAudnA7h3_Al5kJydzLjw6RzZC3Q6OvnLEYlhNW7HA";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", 123)
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateCustomClaimOfTypeLong() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjo5MjIzMzcyMDM2ODU0Nzc2MDB9.km-IwQ5IDnTZFmuJzhSgvjTzGkn_Z5X29g4nAuVC56I";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", 922337203685477600L)
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateCustomClaimOfTypeDouble() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoyMy40NX0.7pyX2OmEGaU9q15T8bGFqRm-d3RVTYnqmZNZtxMKSlA";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", 23.45)
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateCustomClaimOfTypeBoolean() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjp0cnVlfQ.FwQ8VfsZNRqBa9PXMinSIQplfLU4-rkCLfIlTLg_MV0";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", true)
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateCustomClaimOfTypeDate() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoxNDc4ODkxNTIxfQ.mhioumeok8fghQEhTKF3QtQAksSvZ_9wIhJmgZLhJ6c";
        Date date = new Date(1478891521000L);
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaim("name", date)
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateCustomArrayClaimOfTypeString() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbInRleHQiLCIxMjMiLCJ0cnVlIl19.lxM8EcmK1uSZRAPd0HUhXGZJdauRmZmLjoeqz4J9yAA";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withArrayClaim("name", "text", "123", "true")
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateCustomArrayClaimOfTypeInteger() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbMSwyLDNdfQ.UEuMKRQYrzKAiPpPLhIVawWkKWA1zj0_GderrWUIyFE";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withArrayClaim("name", 1, 2, 3)
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateCustomArrayClaimOfTypeLong() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbNTAwMDAwMDAwMDAxLDUwMDAwMDAwMDAwMiw1MDAwMDAwMDAwMDNdfQ.vzV7S0gbV9ZAVxChuIt4XZuSVTxMH536rFmoHzxmayM";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withArrayClaim("name", 500000000001L, 500000000002L, 500000000003L)
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateCustomArrayClaimOfTypeLongWhenValueIsInteger() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbMSwyLDNdfQ.UEuMKRQYrzKAiPpPLhIVawWkKWA1zj0_GderrWUIyFE";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withArrayClaim("name", 1L, 2L, 3L)
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldValidateCustomArrayClaimOfTypeLongWhenValueIsIntegerAndLong() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbMSw1MDAwMDAwMDAwMDIsNTAwMDAwMDAwMDAzXX0.PQjb2rPPpYjM2sItZEzZcjS2YbfPCp6xksTSPjpjTQA";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withArrayClaim("name", 1L, 500000000002L, 500000000003L)
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    // Generic Delta
    @SuppressWarnings("RedundantCast")
    @Test
    public void shouldAddDefaultLeewayToDateClaims() throws Exception {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier verifier = JWTVerifier.init(algorithm)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, hasEntry("iat", (Object) 0L));
        assertThat(verifier.claims, hasEntry("exp", (Object) 0L));
        assertThat(verifier.claims, hasEntry("nbf", (Object) 0L));
    }

    @SuppressWarnings("RedundantCast")
    @Test
    public void shouldAddCustomLeewayToDateClaims() throws Exception {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier verifier = JWTVerifier.init(algorithm)
                .acceptLeeway(1234L)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, hasEntry("iat", (Object) 1234L));
        assertThat(verifier.claims, hasEntry("exp", (Object) 1234L));
        assertThat(verifier.claims, hasEntry("nbf", (Object) 1234L));
    }

    @SuppressWarnings("RedundantCast")
    @Test
    public void shouldOverrideDefaultIssuedAtLeeway() throws Exception {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier verifier = JWTVerifier.init(algorithm)
                .acceptLeeway(1234L)
                .acceptIssuedAt(9999L)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, hasEntry("iat", (Object) 9999L));
        assertThat(verifier.claims, hasEntry("exp", (Object) 1234L));
        assertThat(verifier.claims, hasEntry("nbf", (Object) 1234L));
    }

    @SuppressWarnings("RedundantCast")
    @Test
    public void shouldOverrideDefaultExpiresAtLeeway() throws Exception {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier verifier = JWTVerifier.init(algorithm)
                .acceptLeeway(1234L)
                .acceptExpiresAt(9999L)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, hasEntry("iat", (Object) 1234L));
        assertThat(verifier.claims, hasEntry("exp", (Object) 9999L));
        assertThat(verifier.claims, hasEntry("nbf", (Object) 1234L));
    }

    @SuppressWarnings("RedundantCast")
    @Test
    public void shouldOverrideDefaultNotBeforeLeeway() throws Exception {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier verifier = JWTVerifier.init(algorithm)
                .acceptLeeway(1234L)
                .acceptNotBefore(9999L)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, hasEntry("iat", (Object) 1234L));
        assertThat(verifier.claims, hasEntry("exp", (Object) 1234L));
        assertThat(verifier.claims, hasEntry("nbf", (Object) 9999L));
    }

    @Test
    public void shouldThrowOnNegativeCustomLeeway() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Leeway value can't be negative.");
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier.init(algorithm)
                .acceptLeeway(-1);
    }

    // Expires At
    @Test
    public void shouldValidateExpiresAtWithLeeway() throws Exception {
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
                .build(mockNow)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidExpiresAtIfPresent() throws Exception {
        exception.expect(TokenExpiredException.class);
        exception.expectMessage(startsWith("The Token has expired on"));

        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc1OTJ9.isvT0Pqx0yjnZk53mUFSeYFJLDs-Ls9IsNAm86gIdZo";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"));
        verification
                .build(mockOneSecondLater)
                .verify(token);
    }

    @Test
    public void shouldThrowOnNegativeExpiresAtLeeway() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Leeway value can't be negative.");
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier.init(algorithm)
                .acceptExpiresAt(-1);
    }

    // Not before
    @Test
    public void shouldValidateNotBeforeWithLeeway() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE0Nzc1OTJ9.wq4ZmnSF2VOxcQBxPLfeh1J2Ozy1Tj5iUaERm3FKaw8";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"))
                .acceptNotBefore(2);
        DecodedJWT jwt = verification
                .build(mockOneSecondEarlier)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidNotBeforeIfPresent() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage(startsWith("The Token can't be used before"));

        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE0Nzc1OTJ9.wq4ZmnSF2VOxcQBxPLfeh1J2Ozy1Tj5iUaERm3FKaw8";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"));
        verification
                .build(mockOneSecondEarlier)
                .verify(token);
    }

    @Test
    public void shouldValidateNotBeforeIfPresent() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc1OTJ9.isvT0Pqx0yjnZk53mUFSeYFJLDs-Ls9IsNAm86gIdZo";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"));
        DecodedJWT jwt = verification
                .build(mockNow)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnNegativeNotBeforeLeeway() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Leeway value can't be negative.");
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier.init(algorithm)
                .acceptNotBefore(-1);
    }

    // Issued At with future date
    @Test(expected = InvalidClaimException.class)
    public void shouldThrowOnFutureIssuedAt() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0Nzc1OTJ9.CWq-6pUXl1bFg81vqOUZbZrheO2kUBd2Xr3FUZmvudE";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"));

        DecodedJWT jwt = verification.build(mockOneSecondEarlier).verify(token);
        assertThat(jwt, is(notNullValue()));
    }

    // Issued At with future date and ignore flag
    @Test
    public void shouldSkipIssuedAtVerificationWhenFlagIsPassed() throws Exception {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0Nzc1OTJ9.CWq-6pUXl1bFg81vqOUZbZrheO2kUBd2Xr3FUZmvudE";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"));
        verification.ignoreIssuedAt();

        DecodedJWT jwt = verification.build(mockOneSecondEarlier).verify(token);
        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidIssuedAtIfPresent() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage(startsWith("The Token can't be used before"));

        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0Nzc1OTJ9.0WJky9eLN7kuxLyZlmbcXRL3Wy8hLoNCEk5CCl2M4lo";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"));
        verification
                .build(mockOneSecondEarlier)
                .verify(token);
    }

    @Test
    public void shouldOverrideAcceptIssuedAtWhenIgnoreIssuedAtFlagPassedAndSkipTheVerification() throws Exception {
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
    public void shouldValidateIssuedAtIfPresent() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0Nzc1OTJ9.0WJky9eLN7kuxLyZlmbcXRL3Wy8hLoNCEk5CCl2M4lo";
        JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWTVerifier.init(Algorithm.HMAC256("secret"));
        DecodedJWT jwt = verification
                .build(mockNow)
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnNegativeIssuedAtLeeway() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Leeway value can't be negative.");
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier.init(algorithm)
                .acceptIssuedAt(-1);
    }

    @Test
    public void shouldValidateJWTId() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqd3RfaWRfMTIzIn0.0kegfXUvwOYioP8PDaLMY1IlV8HOAzSVz3EGL7-jWF4";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withJWTId("jwt_id_123")
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnInvalidJWTId() throws Exception {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'jti' value doesn't match the required one.");
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqd3RfaWRfMTIzIn0.0kegfXUvwOYioP8PDaLMY1IlV8HOAzSVz3EGL7-jWF4";
        JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withJWTId("invalid")
                .build()
                .verify(token);
    }

    @Test
    public void shouldRemoveClaimWhenPassingNull() throws Exception {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier verifier = JWTVerifier.init(algorithm)
                .withIssuer("iss")
                .withIssuer((String) null)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, not(hasKey("iss")));

        verifier = JWTVerifier.init(algorithm)
                .withIssuer("iss")
                .withIssuer((String[]) null)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, not(hasKey("iss")));
    }

    @Test
    public void shouldRemoveIssuerWhenPassingNullReference() throws Exception {
        Algorithm algorithm = mock(Algorithm.class);
        JWTVerifier verifier = JWTVerifier.init(algorithm)
                .withIssuer((String) null)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, not(hasKey("iss")));

        verifier = JWTVerifier.init(algorithm)
                .withIssuer((String[]) null)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, not(hasKey("iss")));

        verifier = JWTVerifier.init(algorithm)
                .withIssuer()
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, not(hasKey("iss")));

        String emptyIss = "  ";
        verifier = JWTVerifier.init(algorithm)
                .withIssuer(emptyIss)
                .build();

        assertThat(verifier.claims, is(notNullValue()));
        assertThat(verifier.claims, hasEntry("iss", Collections.singletonList(emptyIss)));
    }

    @Test
    public void shouldSkipClaimValidationsIfNoClaimsRequired() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M";
        DecodedJWT jwt = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .build()
                .verify(token);

        assertThat(jwt, is(notNullValue()));
    }

    @Test
    public void shouldThrowWhenVerifyingClaimPresenceButClaimNotPresent() {
        exception.expect(InvalidClaimException.class);
        exception.expectMessage("The Claim 'missing' is not present in the JWT.");

        String jwt = JWTCreator.init()
                .withClaim("custom", "")
                .sign(Algorithm.HMAC256("secret"));

        JWTVerifier verifier = JWTVerifier.init(Algorithm.HMAC256("secret"))
                .withClaimPresence("missing")
                .build();

        verifier.verify(jwt);
    }

    @Test
    public void shouldThrowWhenVerifyingClaimPresenceWhenClaimNameIsNull() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Custom Claim's name can't be null.");

        String jwt = JWTCreator.init()
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
}
