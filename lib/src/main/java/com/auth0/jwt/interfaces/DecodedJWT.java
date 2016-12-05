package com.auth0.jwt.interfaces;

/**
 * Class that represents a Json Web Token that was decoded from it's string representation.
 */
public interface DecodedJWT extends Payload, Header, Signature {
    String getToken();
}
