package com.auth0.jwt;

import java.util.Date;

/**
 * The Clock class is used to wrap calls to Date class.
 */
public class Clock {

    public Clock() {
    }

    /**
     * Returns a new Date representing Today's time.
     *
     * @return a new Date representing Today's time.
     */
    public Date getToday() {
        return new Date();
    }
}
