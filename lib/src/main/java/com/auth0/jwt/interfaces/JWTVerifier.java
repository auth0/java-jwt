package com.auth0.jwt.interfaces;

import com.auth0.jwt.exceptions.JWTVerificationException;

public interface JWTVerifier {
  DecodedJWT verify(String token) throws JWTVerificationException;
}
