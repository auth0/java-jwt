package com.auth0.jwtdecodejava.interfaces;

import com.auth0.jwtdecodejava.enums.Algorithm;
import com.sun.istack.internal.Nullable;

import java.util.Map;

public interface Header {

    @Nullable
    Algorithm getAlgorithm();

    @Nullable
    String getType();

    @Nullable
    String getContentType();

}
