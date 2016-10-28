package com.auth0.jwtdecodejava.interfaces;

public interface Signature {

    /**
     * Get the Signature from this Payload as a Base64 encoded String.
     *
     * @return the Signature of the Payload.
     */
    String getSignature();
}
