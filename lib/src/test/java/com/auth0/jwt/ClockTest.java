package com.auth0.jwt;

import org.junit.Test;

import java.util.Date;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.*;

public class ClockTest {

    @Test
    public void shouldGetToday() throws Exception{
        Clock clock = new Clock();
        Date clockToday = clock.getToday();
        assertThat(clockToday, is(notNullValue()));
    }

}