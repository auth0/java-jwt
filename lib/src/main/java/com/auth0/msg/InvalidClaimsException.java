package com.auth0.msg;

public class InvalidClaimsException extends RuntimeException {
    public InvalidClaimsException(String message) {
        this(message, null);
    }

    public InvalidClaimsException(String message, Throwable cause) {
        super(message, cause);
    }
}
