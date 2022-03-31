package com.auth0.jwt.interfaces;

import java.security.PrivateKey;

/**
 * Generic representation of Private Key with its Key ID.
 *
 * @param <R> the class that represents the Private Key
 */
public interface PrivateKeyDetail<R extends PrivateKey> {
    /**
     * Getter for the Private Key instance. Used to sign the content on the JWT signing stage.
     *
     * @return the Private Key instance
     */
    R getPrivateKey();

    /**
     * Getter for the Id of the Private Key used to sign the tokens.
     * This represents the `kid` claim and will be placed in the Header.
     *
     * @return the Key Id that identifies the Private Key or null if it's not specified.
     */
    String getPrivateKeyId();
}
