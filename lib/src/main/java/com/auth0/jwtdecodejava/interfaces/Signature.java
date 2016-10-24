package com.auth0.jwtdecodejava.interfaces;

import com.sun.istack.internal.Nullable;

public interface Signature {

    /**
     * Get the Signature from this Payload as a Base64 encoded String.
     *
     * @return the Signature of the Payload.
     */
    @Nullable
    String getSignature();
}
