package com.auth0.jwt;

import com.auth0.jwt.interfaces.Clock;
import org.jetbrains.annotations.NotNull;

import java.util.Date;

/**
 * Default Clock implementation used for verification.
 *
 * @see Clock
 * @see JWTVerifier
 * <p>
 * This class is thread-safe.
 */
final class ClockImpl implements Clock {

    ClockImpl() {
    }

    @NotNull
    @Override
    public Date getToday() {
        return new Date();
    }
}
