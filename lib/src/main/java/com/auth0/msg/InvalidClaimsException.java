package com.auth0.msg;

/**
 * A runtime exception that is thrown when there is an invalid claim in a Message object type
 */
public class InvalidClaimsException extends RuntimeException {
    public InvalidClaimsException(String message) {
        this(message, null);
    }

    public InvalidClaimsException(String message, Throwable cause) {
        super(message, cause);
    }
}
