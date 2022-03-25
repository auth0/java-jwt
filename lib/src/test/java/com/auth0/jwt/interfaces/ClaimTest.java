package com.auth0.jwt.interfaces;

import com.auth0.jwt.exceptions.JWTDecodeException;
import org.junit.Test;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class ClaimTest {

    @Test
    public void shouldGetInstantUsingDefault() {
        Date date = new Date(1646667492000L);
        Claim claim = new ClaimImplForTest(date);
        assertThat(claim.asInstant(), is(date.toInstant()));
    }

    @Test
    public void shouldGetNullInstantUsingDefault() {
        Claim claim = new ClaimImplForTest(null);
        assertThat(claim.asInstant(), is(nullValue()));
    }

    /**
     * Implementation that does not override {@code asInstant()}
     */
    static class ClaimImplForTest implements Claim {
        private final Date date;

        ClaimImplForTest(Date date) {
            this.date = date;
        }

        @Override
        public boolean isNull() {
            return false;
        }

        @Override
        public Boolean asBoolean() {
            return null;
        }

        @Override
        public Integer asInt() {
            return null;
        }

        @Override
        public Long asLong() {
            return null;
        }

        @Override
        public Double asDouble() {
            return null;
        }

        @Override
        public String asString() {
            return null;
        }

        @Override
        public Date asDate() {
            return date;
        }

        @Override
        public <T> T[] asArray(Class<T> clazz) throws JWTDecodeException {
            return null;
        }

        @Override
        public <T> List<T> asList(Class<T> clazz) throws JWTDecodeException {
            return null;
        }

        @Override
        public Map<String, Object> asMap() throws JWTDecodeException {
            return null;
        }

        @Override
        public <T> T as(Class<T> tClazz) throws JWTDecodeException {
            return null;
        }
    }
}
