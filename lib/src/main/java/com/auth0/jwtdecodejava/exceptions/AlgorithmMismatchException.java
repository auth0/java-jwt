package com.auth0.jwtdecodejava.exceptions;

public class AlgorithmMismatchException extends JWTException{
    public AlgorithmMismatchException(String message) {
        super(message);
    }
}
