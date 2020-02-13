package com.auth0.jwt;

import com.auth0.jwt.interfaces.Clock;

import java.time.Instant;

final class ClockImpl implements Clock {

    ClockImpl() {

    }

    @Override
    public Instant getToday() {
        return Instant.now();
    }
}
