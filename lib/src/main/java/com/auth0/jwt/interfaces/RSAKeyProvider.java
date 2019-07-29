package com.auth0.jwt.interfaces;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * RSA Public/Private Key provider.
 */
public interface RSAKeyProvider extends KeyProvider<PublicKey, PrivateKey> {
}
