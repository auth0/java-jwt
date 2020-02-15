package com.auth0.jwt;

import com.auth0.jwt.interfaces.Clock;

import java.time.Instant;
import java.util.Date;

final class ClockImpl implements Clock {

    ClockImpl() {

    }

    @Override
    public Instant getNow() {
        return Instant.now();
    }

    @Override
    public Date getToday() {
        return new Date();
    }
}
