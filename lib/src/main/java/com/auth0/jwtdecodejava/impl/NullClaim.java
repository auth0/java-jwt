package com.auth0.jwtdecodejava.impl;

import com.auth0.jwtdecodejava.interfaces.Claim;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public final class NullClaim implements Claim {

    @Override
    public boolean isMissing() {
        return false;
    }

    @Override
    public boolean isNull() {
        return true;
    }

    @Override
    public Boolean asBoolean() {
        return null;
    }

    @Override
    public Integer asInt() {
        return null;
    }

    @Override
    public Double asDouble() {
        return null;
    }

    @Override
    public String asString() {
        return null;
    }

    @Override
    public Date asDate() {
        return null;
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T> T[] asArray(Class<T> tClazz) throws Exception {
        return (T[]) Array.newInstance(tClazz, 0);
    }

    @Override
    public <T> List<T> asList(Class<T> tClazz) throws Exception {
        return new ArrayList<>();
    }
}
