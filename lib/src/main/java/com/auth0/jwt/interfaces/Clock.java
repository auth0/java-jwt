package com.auth0.jwt.interfaces;

import java.time.Instant;

/**
 * The Clock class is used to wrap calls to Date class.
 */
public interface Clock {
    /**
     * Returns a new Instant representing Today's time.
     *
     * @return a new Instant representing Today's time.
     */
    Instant getToday();
}
