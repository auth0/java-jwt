package com.auth0.jwtdecodejava;

import com.auth0.jwtdecodejava.exceptions.JWTException;
import com.auth0.jwtdecodejava.impl.BaseClaim;
import com.sun.istack.internal.NotNull;

import java.util.Date;
import java.util.List;

public class MissingClaim extends BaseClaim {

    public MissingClaim(@NotNull String name) {
        super(name);
    }

    @Override
    public boolean isMissing() {
        return true;
    }

    @Override
    public boolean isNull() {
        return false;
    }

    @Override
    public Boolean asBoolean() {
        throw new JWTException("Missing Claim");
    }

    @Override
    public Integer asInt() {
        throw new JWTException("Missing Claim");
    }

    @Override
    public Double asDouble() {
        throw new JWTException("Missing Claim");
    }

    @Override
    public String asString() {
        throw new JWTException("Missing Claim");
    }

    @Override
    public Date asDate() {
        throw new JWTException("Missing Claim");
    }

    @Override
    public <T> T[] asArray(Class<T> tClazz) throws Exception {
        throw new JWTException("Missing Claim");
    }

    @Override
    public <T> List<T> asList(Class<T> tClazz) throws Exception {
        throw new JWTException("Missing Claim");
    }
}
