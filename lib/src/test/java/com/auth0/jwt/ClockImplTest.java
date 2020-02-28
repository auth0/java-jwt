package com.auth0.jwt;

import com.auth0.jwt.interfaces.Clock;
import org.junit.Test;

import java.util.Date;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.*;

public class ClockImplTest {

    @Test
    public void shouldGetToday() {
        Clock clock = new ClockImpl();
        Date clockToday = clock.getToday();
        assertThat(clockToday, is(notNullValue()));
    }

}