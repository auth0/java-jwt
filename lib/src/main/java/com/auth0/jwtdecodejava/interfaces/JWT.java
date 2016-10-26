package com.auth0.jwtdecodejava.interfaces;

public interface JWT extends Payload, Header {

    String getSignature();

    //TODO replace with advanced validations
    boolean isExpired();
}
