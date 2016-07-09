package com.auth0.jwt;

/**
 * Represents General Exception related to Verification
 */
public class JWTVerifyException extends Exception {

	public JWTVerifyException() {}

	public JWTVerifyException(final String message, final Throwable cause) {
		super(message, cause);
	}

	public JWTVerifyException(final String message) {
		super(message);
	}

}
