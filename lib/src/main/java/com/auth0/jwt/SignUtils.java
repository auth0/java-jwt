package com.auth0.jwt;

import com.auth0.jwt.exceptions.JWTDecodeException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

abstract class SignUtils {

    /**
     * Encodes the given bytes into a UTF-8 String representation.
     *
     * @param source the source of the .
     * @return a UTF-8 String representing the source bytes.
     * @throws NullPointerException if the UTF-8 Charset isn't initialized.
     */
    static String toUTF8String(byte[] source) throws NullPointerException {
        return StringUtils.newStringUtf8(source);
    }

    /**
     * Decodes a given String from it's Base64 String representation into an array of bytes.
     *
     * @param source the source bytes to decode.
     * @return an array of bytes representing the Base64 decoded source.
     */
    static byte[] base64Decode(String source) {
        return Base64.decodeBase64(source);
    }

    /**
     * Encodes a given String into it's Base64 String representation.
     *
     * @param source the source bytes to encode.
     * @return a String containing Base64 characters.
     */
    static String base64Encode(byte[] source) {
        return Base64.encodeBase64URLSafeString(source);
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
