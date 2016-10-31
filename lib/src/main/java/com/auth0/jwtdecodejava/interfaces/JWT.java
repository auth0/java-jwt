package com.auth0.jwtdecodejava.interfaces;

/**
 * The JWT class represents a Json Web Token.
 */
public interface JWT extends Payload, Header {

    /**
     * Returns the JWT's Signature without any transformation. The Signature is located in the 3rd part of the token.
     *
     * @return the JWT's Signature.
     */
    String getSignature();

    //TODO replace with advanced validations
    boolean isExpired();
}
