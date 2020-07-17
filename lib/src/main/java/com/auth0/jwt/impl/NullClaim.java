package com.auth0.jwt.impl;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * The {@link NullClaim} class is a Claim implementation that returns null when any of it's methods it's called.
 */
public class NullClaim implements Claim {
    @Override
    public boolean isNull() {
        return true;
    }

    @Nullable
    @Override
    public Boolean asBoolean() {
        return null;
    }

    @Nullable
    @Override
    public Integer asInt() {
        return null;
    }

    @Nullable
    @Override
    public Long asLong() {
        return null;
    }

    @Nullable
    @Override
    public Double asDouble() {
        return null;
    }

    @Nullable
    @Override
    public String asString() {
        return null;
    }

    @Nullable
    @Override
    public Date asDate() {
        return null;
    }

    @Nullable
    @Override
    public <T> T [] asArray(@NotNull Class<T> tClazz) throws JWTDecodeException {
        return null;
    }

    @Nullable
    @Override
    public <T> List<T> asList(@NotNull Class<T> tClazz) throws JWTDecodeException {
        return null;
    }

    @Nullable
    @Override
    public Map<String, Object> asMap() throws JWTDecodeException {
        return null;
    }

    @Nullable
    @Override
    public <T> T as(@NotNull Class<T> tClazz) throws JWTDecodeException {
        return null;
    }
}
