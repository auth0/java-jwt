package com.auth0.msg;

/**
 * A runtime exception that is thrown when there is an issue with serialization of the Message type
 */
public class SerializationException extends RuntimeException {
    public SerializationException(String message) {
        this(message, null);
    }

    public SerializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
