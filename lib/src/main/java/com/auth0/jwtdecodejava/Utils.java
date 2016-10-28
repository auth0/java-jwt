package com.auth0.jwtdecodejava;

import com.auth0.jwtdecodejava.enums.Algorithm;
import com.auth0.jwtdecodejava.exceptions.JWTException;
import com.sun.istack.internal.Nullable;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Utils {

    @Nullable
    public static String base64Decode(String string) throws JWTException {
        String decoded;
        try {
            decoded = StringUtils.newStringUtf8(Base64.decodeBase64(string));
        } catch (NullPointerException e) {
            throw new JWTException("Received bytes didn't correspond to a valid Base64 encoded string.", e);
        }
        return decoded;
    }

    @Nullable
    public static String base64Encode(String string) throws JWTException {
        String encoded;
        try {
            encoded = StringUtils.newStringUtf8(Base64.encodeBase64(string.getBytes(), false, true));
        } catch (NullPointerException e) {
            throw new JWTException("Received bytes didn't correspond to a valid Base64 encoded string.", e);
        }
        return encoded;
    }

    public static boolean verifyHS(String[] jwtParts, String secret, Algorithm algorithm) throws NoSuchAlgorithmException, InvalidKeyException {
        if (secret == null) {
            throw new IllegalArgumentException("The Secret cannot be null");
        }
        if (algorithm != Algorithm.HS256 && algorithm != Algorithm.HS384 && algorithm != Algorithm.HS512) {
            throw new IllegalArgumentException("The Algorithm must be one of HS256, HS384, or HS512.");
        }
        Mac mac = Mac.getInstance(algorithm.toString());
        mac.init(new SecretKeySpec(secret.getBytes(), algorithm.toString()));
        String message = String.format("%s.%s", jwtParts[0], jwtParts[1]);
        byte[] result = mac.doFinal(message.getBytes());
        return MessageDigest.isEqual(result, Base64.decodeBase64(jwtParts[2]));
    }

    public static String[] splitToken(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new JWTException(String.format("The token was expected to have 3 parts, but got %s.", parts.length));
        }
        return parts;
    }
}
