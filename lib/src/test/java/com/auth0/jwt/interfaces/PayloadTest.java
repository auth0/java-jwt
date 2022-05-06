package com.auth0.jwt.interfaces;

import org.junit.Test;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class PayloadTest {

    @Test
    public void shouldGetInstantFromDefault() {
        Date date = new Date(1646667492000L);
        Payload payload = new PayloadImplForTest(date);
        assertThat(payload.getExpiresAtAsInstant(), is(date.toInstant()));
        assertThat(payload.getIssuedAtAsInstant(), is(date.toInstant()));
        assertThat(payload.getNotBeforeAsInstant(), is(date.toInstant()));
    }

    @Test
    public void shouldGetInstantFromDefaultAsNu() {
        Payload payload = new PayloadImplForTest(null);
        assertThat(payload.getExpiresAtAsInstant(), is(nullValue()));
        assertThat(payload.getIssuedAtAsInstant(), is(nullValue()));
        assertThat(payload.getNotBeforeAsInstant(), is(nullValue()));
    }

    static class PayloadImplForTest implements Payload {
        private final Date date;

        PayloadImplForTest(Date date) {
            this.date = date;
        }

        @Override
        public String getIssuer() {
            return null;
        }

        @Override
        public String getSubject() {
            return null;
        }

        @Override
        public List<String> getAudience() {
            return null;
        }

        @Override
        public Date getExpiresAt() {
            return date;
        }

        @Override
        public Date getNotBefore() {
            return date;
        }

        @Override
        public Date getIssuedAt() {
            return date;
        }

        @Override
        public String getId() {
            return null;
        }

        @Override
        public Claim getClaim(String name) {
            return null;
        }

        @Override
        public Map<String, Claim> getClaims() {
            return null;
        }
    }
}
