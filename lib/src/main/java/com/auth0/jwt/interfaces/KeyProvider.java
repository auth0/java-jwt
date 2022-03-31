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
     * Getter for the Public Key instance with the given Id. Used to verify the signature on the JWT verification stage.
     *
     * @param keyId the Key Id specified in the Token's Header or null if none is available.
     *              Provides a hint on which Public Key to use to verify the token's signature.
     * @return the Public Key instance
     */
    U getPublicKeyById(String keyId);

    /**
     * Getter for the Private Key instance. Used to sign the content on the JWT signing stage.
     *
     * @return the Private Key instance
     * @deprecated Use {@link KeyProvider#getPrivateKeyDetails()} instead
     */
    R getPrivateKey();

    /**
     * Getter for the Id of the Private Key used to sign the tokens.
     * This represents the `kid` claim and will be placed in the Header.
     *
     * @return the Key Id that identifies the Private Key or null if it's not specified.
     * @deprecated Use {@link KeyProvider#getPrivateKeyDetails()} instead
     */
    String getPrivateKeyId();

    /**
     * Getter for the Private Key instance along with its Id.
     * Used to sign the content on the JWT signing stage.
     *
     * @return the Private Key Details instance
     */
    default PrivateKeyDetail<R> getPrivateKeyDetails() {
        return new PrivateKeyDetail<R>() {
            @Override
            public R getPrivateKey() {
                return KeyProvider.this.getPrivateKey();
            }

            @Override
            public String getPrivateKeyId() {
                return KeyProvider.this.getPrivateKeyId();
            }
        };
    }
}
