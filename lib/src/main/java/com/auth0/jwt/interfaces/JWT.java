package com.auth0.jwt.interfaces;

/**
 * The JWT class represents a Json Web Token.
 */
public interface JWT extends Payload, Header, Signature {

    /**
     * Returns the String representation of the token.
     *
     * @return the String representation of the token.
     */
    String toString();
}
