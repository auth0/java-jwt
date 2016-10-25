package com.auth0.jwtdecodejava.interfaces;

import java.io.IOException;

public interface JWTPartsParser {

    Payload parsePayload(String json) throws IOException;

    Header parseHeader(String json) throws IOException;
}
