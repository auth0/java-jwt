package com.auth0.jwtdecodejava.interfaces;

import com.sun.istack.internal.Nullable;

import java.util.Map;

public interface Header {

    /**
     * Get the Header values from this Payload as a Map of Strings.
     *
     * @return the Header values of the Payload.
     */
    @Nullable
    Map<String, String> getHeader();

}
