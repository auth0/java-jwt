package com.auth0.jwtdecodejava.interfaces;

/**
 * The Signature class represents the 1st part of the JWT, where the Header value is hold.
 */
public interface Header {

    /**
     * Getter for the Algorithm "alg" claim defined in the JWT's Header. If the claim is missing it will return null.
     *
     * @return the Algorithm defined or null.
     */
    String getAlgorithm();

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
