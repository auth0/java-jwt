package com.auth0.jwtdecodejava.interfaces;

import com.auth0.jwtdecodejava.exceptions.JWTException;

public interface JWTPartsParser {

    Payload parsePayload(String json) throws JWTException;

    Header parseHeader(String json) throws JWTException;
}
