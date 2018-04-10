package com.auth0.msg;

public class SerializationException extends RuntimeException {
    public SerializationException(String message) {
        this(message, null);
    }

    public SerializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
