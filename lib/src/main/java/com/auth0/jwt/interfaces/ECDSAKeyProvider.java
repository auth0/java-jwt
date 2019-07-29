package com.auth0.jwt.interfaces;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Elliptic Curve (EC) Public/Private Key provider.
 */
public interface ECDSAKeyProvider extends KeyProvider<PublicKey, PrivateKey> {
}
