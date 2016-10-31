package com.auth0.jwtdecodejava.interfaces;

/**
 * The JWT class represents a Json Web Token.
 */
public interface JWT extends Payload, Header, Signature {

    //TODO replace with advanced validations
    boolean isExpired();
}
