package com.auth0.jwtdecodejava.impl;

import com.auth0.jwtdecodejava.exceptions.JWTException;
import com.auth0.jwtdecodejava.interfaces.Claim;

import java.util.Date;
import java.util.List;

public class BaseClaim implements Claim {
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

    @Override
    public <T> T[] asArray(Class<T> tClazz) throws JWTException {
        return null;
    }

    @Override
    public <T> List<T> asList(Class<T> tClazz) throws JWTException {
        return null;
    }
}
