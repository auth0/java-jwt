package com.auth0.jwtdecodejava;

import com.auth0.jwtdecodejava.algorithms.HSAlgorithm;
import com.auth0.jwtdecodejava.algorithms.RSAlgorithm;
import com.auth0.jwtdecodejava.exceptions.JWTDecodeException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

class SignUtils {

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

    /**
     * Verify the given JWT parts using a specific HS Algorithm and a given secret.
     *
     * @param algorithm the HSAlgorithm to use. Must be one of HS256, HS384, or HS512.
     * @param jwtParts  a valid array of size 3 representing the JWT parts.
     * @param secret    the secret used when signing the token's content.
     * @return whether the Token's signature is valid or not.
     * @throws NoSuchAlgorithmException if the chosen algorithm isn't present.
     * @throws InvalidKeyException
     */
    static boolean verifyHS(HSAlgorithm algorithm, String[] jwtParts, String secret) throws NoSuchAlgorithmException, InvalidKeyException {
        if (secret == null) {
            throw new IllegalArgumentException("The Secret cannot be null");
        }
        if (algorithm == null) {
            throw new IllegalArgumentException("The Algorithm must be one of HS256, HS384, or HS512.");
        }

        Mac mac = Mac.getInstance(algorithm.describe());
        mac.init(new SecretKeySpec(secret.getBytes(), algorithm.describe()));
        String message = String.format("%s.%s", jwtParts[0], jwtParts[1]);
        byte[] result = mac.doFinal(message.getBytes());
        return MessageDigest.isEqual(result, Base64.decodeBase64(jwtParts[2]));
    }

    static boolean verifyRS(RSAlgorithm algorithm, String[] jwtParts, PublicKey publicKey) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        if (publicKey == null) {
            throw new IllegalArgumentException("The PublicKey cannot be null");
        }
        if (algorithm == null) {
            throw new IllegalArgumentException("The Algorithm must be one of RS256, RS384, or RS512.");
        }

        final String content = String.format("%s.%s", jwtParts[0], jwtParts[1]);
        Signature s = Signature.getInstance(algorithm.describe());
        s.initVerify(publicKey);
        s.update(content.getBytes());
        return s.verify(Base64.decodeBase64(jwtParts[2]));
    }
}
