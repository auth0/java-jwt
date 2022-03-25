package com.auth0.jwt.impl;

/**
 * Contains the claim name for all Public claims.
 */
public interface PublicClaims {

    //Header
    String ALGORITHM = "alg";
    String CONTENT_TYPE = "cty";
    String TYPE = "typ";
    String KEY_ID = "kid";

    //Payload
    String ISSUER = "iss";
    String SUBJECT = "sub";
    String EXPIRES_AT = "exp";
    String NOT_BEFORE = "nbf";
    String ISSUED_AT = "iat";
    String JWT_ID = "jti";
    String AUDIENCE = "aud";

}
