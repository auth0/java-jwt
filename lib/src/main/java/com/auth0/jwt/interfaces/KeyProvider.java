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
     * @param keyId the Key Id specified in the Token's Header or null if none is available. Provides a hint on which Public Key to use to verify the token's signature.
     * @return the Public Key instance
     */
    U getPublicKey(String keyId);

    /**
     * Getter for the Private Key instance, used to sign the content.
     *
     * @return the Private Key instance
     */
    R getPrivateKey();

    /**
     * Getter for the Id of the Private Key used to sign the tokens. This represents the `kid` claim and will be placed in the Header if no other "Key Id" has been set already.
     *
     * @return the Key Id that identifies the Signing Key or null if it's not specified.
     */
    String getSigningKeyId();
}
