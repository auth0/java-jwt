package com.auth0.jwt;

import com.auth0.jwt.interfaces.Clock;
import org.junit.Test;

import java.time.Instant;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;

public class ClockImplTest {

    @Test
    public void shouldGetToday() {
        Clock clock = new ClockImpl();
        Instant clockToday = clock.getToday();
        assertThat(clockToday, is(notNullValue()));
    }

}