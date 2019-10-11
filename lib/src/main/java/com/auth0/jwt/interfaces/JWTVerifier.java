package com.auth0.jwt.interfaces;

import com.auth0.jwt.exceptions.JWTVerificationException;


public interface JWTVerifier {
  
  /**
   * Performs the verification against the given Token
   *
   * @param token to verify.
   * @return a verified and decoded JWT.
   * @throws JWTVerificationException if any of the verification steps fail
   */
  DecodedJWT verify(String token) throws JWTVerificationException;

  /**
   * Performs the verification against the given decoded JWT
   *
   * @param jwt to verify.
   * @return a verified and decoded JWT.
   * @throws JWTVerificationException if any of the verification steps fail
   */
  DecodedJWT verify(DecodedJWT jwt) throws JWTVerificationException;

  /**
   * Performs validity of the JWT token without throwing Exception.
   * Useful for using with tools which does instrumentation to now show
   * unnecessary Exceptions. Also useful for functional programming.
   * @param token to check validity
   * @return if it is a valid JWT token return true, else false
   */
  Boolean isValid(String token);

  /**
   * Performs validity of the given decoded JWT without throwing Exception.
   * Useful for using with tools which does instrumentation to now show
   * unnecessary Exceptions. Also useful for functional programming.
   * @param token to check validity
   * @return if it is a valid JWT token return true, else false
   */
  Boolean isValid(DecodedJWT token);
}
