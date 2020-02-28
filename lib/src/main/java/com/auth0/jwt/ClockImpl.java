package com.auth0.jwt;

import com.auth0.jwt.interfaces.Clock;

import java.util.Date;

final class ClockImpl implements Clock {

    ClockImpl() {

    }

    @Override
    public Date getToday() {
        return new Date();
    }
}
