package com.auth0.jwtdecodejava.interfaces;

import com.auth0.jwtdecodejava.algorithms.Algorithm;

/**
 * The Signature class represents the 1st part of the JWT, where the Header value is hold.
 */
public interface Header {

    /**
     * Getter for the Algorithm "alg" claim defined in the JWT's Header. If the claim is missing or the value isn't valid, it will return null.
     *
     * @return the Algorithm defined or null.
     */
    Algorithm getAlgorithm();

    /**
     * Getter for the Type "typ" claim defined in the JWT's Header. If the claim is missing it will return null.
     *
     * @return the Type defined or null.
     */
    String getType();

    /**
     * Getter for the Content Type "cty" claim defined in the JWT's Header. If the claim is missing it will return null.
     *
     * @return the Content Type defined or null.
     */
    String getContentType();

}
