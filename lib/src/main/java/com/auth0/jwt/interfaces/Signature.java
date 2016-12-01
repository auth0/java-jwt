package com.auth0.jwt.interfaces;

/**
 * The Signature class represents the 3rd part of the DecodedJWT, where the Signature value is hold.
 */
public interface Signature {

    /**
     * Getter for the Signature contained in the DecodedJWT as a Base64 encoded String.
     *
     * @return the Signature of the DecodedJWT.
     */
    String getSignature();
}
