package com.auth0.jwtdecodejava;

import com.auth0.jwtdecodejava.exceptions.JWTException;
import com.auth0.jwtdecodejava.interfaces.Header;
import com.auth0.jwtdecodejava.interfaces.Payload;
import com.auth0.jwtdecodejava.impl.jackson.JacksonConverter;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

public class JWTDecoder {

    private Header header;
    private Payload payload;
    private String signature;

    public JWTDecoder(String jwt) {
        try {
            parseToken(jwt);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public Header getHeader() {
        return header;
    }

    public Payload getPayload() {
        return payload;
    }

    public String getSignature() {
        return signature;
    }

    private void parseToken(String token) throws IOException {
        final String[] parts = splitToken(token);
        final JacksonConverter converter = new JacksonConverter(new ObjectMapper());
//        header = converter.parseHeader(Utils.base64Decode(parts[0]));
        payload = converter.parsePayload(Utils.base64Decode(parts[1]));
        signature = parts[2];
    }

    private String[] splitToken(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new JWTException(String.format("The token was expected to have 3 parts, but got %s.", parts.length));
        }
        return parts;
    }

}
