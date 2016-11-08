package com.auth0.jwt;

import com.auth0.jwt.exceptions.JWTDecodeException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

abstract class SignUtils {

    /**
     * Decodes a given String from it's Base64 string representation into a UTF-8 String.
     *
     * @param source the source of the decode process.
     * @return a UTF-8 String representing the Base64 decoded source.
     * @throws NullPointerException if the UTF-8 Charset isn't initialized.
     */
    static String base64Decode(String source) throws NullPointerException {
        return StringUtils.newStringUtf8(Base64.decodeBase64(source));
    }

    /**
     * Encodes a given String into it's Base64 string representation.
     *
     * @param source the source of the decode process.
     * @return a UTF-8 String encoded into it's Base64 representation.
     * @throws NullPointerException     if the UTF-8 Charset isn't initialized.
     * @throws IllegalArgumentException if the source string is too long.
     */
    static String base64Encode(String source) throws NullPointerException, IllegalArgumentException {
        return StringUtils.newStringUtf8(Base64.encodeBase64(source.getBytes(), false, true));
    }

    /**
     * Splits the given token on the "." chars into a String array with 3 parts.
     *
     * @param token the string to split.
     * @return the array representing the 3 parts of the token.
     * @throws JWTDecodeException if the Token doesn't have 3 parts.
     */
    static String[] splitToken(String token) throws JWTDecodeException {
        String[] parts = token.split("\\.");
        if (parts.length == 2 && token.endsWith(".")) {
            //Tokens with alg='none' have empty String as Signature.
            parts = new String[]{parts[0], parts[1], ""};
        }
        if (parts.length != 3) {
            throw new JWTDecodeException(String.format("The token was expected to have 3 parts, but got %s.", parts.length));
        }
        return parts;
    }

}
