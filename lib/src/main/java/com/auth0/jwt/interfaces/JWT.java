package com.auth0.jwt.interfaces;

/**
 * The JWT class represents a Json Web Token.
 */
public interface JWT extends Payload, Header, Signature {

    /**
     * Tests whether this token's DateTime values IssuedAt, ExpiresAt and NotBefore are time valid.
     * If any of them are missing they won't be taken into account. If the token it's expired it shouldn't be used.
     *
     * @return whether the token should be used or not.
     */
    boolean isExpired();
}
