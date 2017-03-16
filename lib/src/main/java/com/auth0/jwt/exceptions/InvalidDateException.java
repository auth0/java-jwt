package com.auth0.jwt.exceptions;

public class InvalidDateException extends InvalidClaimException {
	private static final long serialVersionUID = -7701609746394348413L;
	
	public InvalidDateException(String message) {
		super(message);
	}
}
