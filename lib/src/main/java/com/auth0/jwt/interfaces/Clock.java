package com.auth0.jwt.interfaces;

import java.time.Instant;
import java.util.Date;

/**
 * The Clock class is used to wrap calls to Date class.
 */
public interface Clock {
    /**
     * Returns a new Instant representing the current time.
     *
     * @return the current time.
     */
    Instant getNow();

    /**
     * Returns a new Date representing Today's time.

     * @return a new Date representing Today's time.
     */
    // TODO - Deprecate this method in favor of getNow()
    Date getToday();
}
