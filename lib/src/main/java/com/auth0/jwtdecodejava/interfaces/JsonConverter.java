package com.auth0.jwtdecodejava.interfaces;

import java.io.IOException;

public interface JsonConverter {

    <T> String toJson(T object, Class<T> tClazz) throws IOException;

    <T> T fromJson(String json, Class<T> tClazz) throws IOException;
}
