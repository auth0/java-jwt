package com.auth0.jwt.interfaces;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Generic Public/Private Key provider.
 *
 * @param <U> the class that represents the Public Key
 * @param <R> the class that represents the Private Key
 */
interface KeyProvider<U extends PublicKey, R extends PrivateKey> {

    /**
     * Getter for the Public Key instance, used to verify the signature.
     *
     * @return the Public Key instance
     */
    U getPublicKey();

    /**
     * Getter for the Private Key instance, used to sign the content.
     *
     * @return the Private Key instance
     */
    R getPrivateKey();
}
