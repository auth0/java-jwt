package com.auth0.jwt;

import org.apache.commons.lang3.Validate;

/**
 * Supported Library Algorithms
 *
 * https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator
 */
public enum Algorithm {

	HS256("HmacSHA256"), HS384("HmacSHA384"), HS512("HmacSHA512"), RS256("SHA256withRSA"), RS384("SHA384withRSA"), RS512("SHA512withRSA");

	private Algorithm(final String value) {
		this.value = value;
	}

	private String value;

	public String getValue() {
		return value;
	}

	public static Algorithm findByName(final String name) throws JWTAlgorithmException {
		Validate.notNull(name);
		try {
			return Algorithm.valueOf(name);
		} catch (IllegalArgumentException e) {
			throw new JWTAlgorithmException("Unsupported algorithm: " + name);
		}
	}

}
