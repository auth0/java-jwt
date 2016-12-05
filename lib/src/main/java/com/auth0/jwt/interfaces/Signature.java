package com.auth0.jwt.interfaces;

/**
 * The Signature class represents the 3rd part of the JWT, where the Signature value is hold.
 */
public interface Signature {

    /**
     * Getter for the Signature contained in the JWT as a Base64 encoded String.
     *
     * @return the Signature of the JWT.
     */
    String getSignature();
}
