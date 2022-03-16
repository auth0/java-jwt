package com.auth0.jwt.interfaces;

import com.auth0.jwt.JWTVerifier;
import org.junit.Test;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiPredicate;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertThrows;

/**
 * Tests for any default method implementations in the {@link Verification} interface.
 */
public class VerificationTest {

    @Test
    public void withInstantClaimShouldUseDefaultImpl() {
        Instant instant = Instant.ofEpochSecond(1478891521);
        Verification verification = new VerificationImplForTest()
                .withClaim("name", instant);

        assertThat(verification, instanceOf(VerificationImplForTest.class));
        assertThat(((VerificationImplForTest)verification).expectedClaims, hasEntry("name", Date.from(instant)));
    }

    @Test
    public void withInstantClaimShouldUseDefaultImplAndHandleNull() {
        Verification verification = new VerificationImplForTest()
                .withClaim("name", (Instant) null);

        assertThat(verification, instanceOf(VerificationImplForTest.class));
        assertThat(((VerificationImplForTest)verification).expectedClaims, hasEntry("name", null));
    }

    @Test
    public void withAnyOfAudienceDeafultImplShouldThrow() {
        assertThrows("withAnyOfAudience", UnsupportedOperationException.class, () -> {
            new VerificationImplForTest().withAnyOfAudience("");
        });
    }

    @Test
    public void withIssuerStringDefaultImplShouldDelegate() {
        Verification verification = new VerificationImplForTest()
                .withIssuer("string");

        assertThat(verification, instanceOf(VerificationImplForTest.class));
        assertThat(((VerificationImplForTest)verification).expectedClaims, hasEntry("iss", new String[]{"string"}));
    }

    static class VerificationImplForTest implements Verification {

        private final Map<String, Object> expectedClaims = new HashMap<>();

        @Override
        public Verification withIssuer(String... issuer) {
            expectedClaims.put("iss", issuer);
            return this;
        }

        @Override
        public Verification withSubject(String subject) {
            return null;
        }

        @Override
        public Verification withAudience(String... audience) {
            return null;
        }

        @Override
        public Verification acceptLeeway(long leeway) throws IllegalArgumentException {
            return null;
        }

        @Override
        public Verification acceptExpiresAt(long leeway) throws IllegalArgumentException {
            return null;
        }

        @Override
        public Verification acceptNotBefore(long leeway) throws IllegalArgumentException {
            return null;
        }

        @Override
        public Verification acceptIssuedAt(long leeway) throws IllegalArgumentException {
            return null;
        }

        @Override
        public Verification withJWTId(String jwtId) {
            return null;
        }

        @Override
        public Verification withClaimPresence(String name) throws IllegalArgumentException {
            return null;
        }

        @Override
        public Verification withClaim(String name, Boolean value) throws IllegalArgumentException {
            return null;
        }

        @Override
        public Verification withClaim(String name, Integer value) throws IllegalArgumentException {
            return null;
        }

        @Override
        public Verification withClaim(String name, Long value) throws IllegalArgumentException {
            return null;
        }

        @Override
        public Verification withClaim(String name, Double value) throws IllegalArgumentException {
            return null;
        }

        @Override
        public Verification withClaim(String name, String value) throws IllegalArgumentException {
            return null;
        }

        @Override
        public Verification withClaim(String name, Date value) throws IllegalArgumentException {
            this.expectedClaims.put(name, value);
            return this;
        }

        @Override
        public Verification withArrayClaim(String name, String... items) throws IllegalArgumentException {
            return null;
        }

        @Override
        public Verification withArrayClaim(String name, Integer... items) throws IllegalArgumentException {
            return null;
        }

        @Override
        public Verification withArrayClaim(String name, Long... items) throws IllegalArgumentException {
            return null;
        }

        @Override
        public Verification withClaim(String name, BiPredicate<Claim, DecodedJWT> predicate) throws IllegalArgumentException {
            return null;
        }

        @Override
        public Verification ignoreIssuedAt() {
            return null;
        }

        @Override
        public JWTVerifier build() {
            return null;
        }
    }
}
