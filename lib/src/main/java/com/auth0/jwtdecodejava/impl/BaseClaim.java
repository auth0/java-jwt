package com.auth0.jwtdecodejava.impl;

import com.auth0.jwtdecodejava.interfaces.Claim;
import com.sun.istack.internal.NotNull;

public abstract class BaseClaim implements Claim {

    private final String name;

    public BaseClaim(@NotNull String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public boolean isMissing() {
        return false;
    }
}
