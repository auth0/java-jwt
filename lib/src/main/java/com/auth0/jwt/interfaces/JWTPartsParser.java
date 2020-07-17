package com.auth0.jwt.interfaces;

import com.auth0.jwt.exceptions.JWTDecodeException;
import org.jetbrains.annotations.NotNull;

/**
 * The JWTPartsParser class defines which parts of the JWT should be converted to it's specific Object representation instance.
 */
public interface JWTPartsParser {

    /**
     * Parses the given JSON into a Payload instance.
     *
     * @param json the content of the Payload in a JSON representation.
     * @return the Payload.
     * @throws JWTDecodeException if the json doesn't have a proper JSON format.
     */
    @NotNull
    Payload parsePayload(@NotNull String json) throws JWTDecodeException;

    /**
     * Parses the given JSON into a Header instance.
     *
     * @param json the content of the Header in a JSON representation.
     * @return the Header.
     * @throws JWTDecodeException if the json doesn't have a proper JSON format.
     */
    @NotNull
    Header parseHeader(@NotNull String json) throws JWTDecodeException;
}
