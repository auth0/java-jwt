package com.auth0.jwtdecodejava.interfaces;

import com.sun.istack.internal.Nullable;

import java.util.Map;

public interface Header {

    @Nullable
    String getAlgorithm();

    @Nullable
    String getType();

    @Nullable
    String getContentType();

}
