package com.auth0.jwt.interfaces;

/**
 * The DecodedJWT class represents a Json Web Token.
 */
public interface DecodedJWT extends Payload, Header, Signature {
    String getToken();
}
