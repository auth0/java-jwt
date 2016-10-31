package com.auth0.jwtdecodejava;

import com.auth0.jwtdecodejava.enums.HSAlgorithm;
import com.auth0.jwtdecodejava.enums.RSAlgorithm;
import com.auth0.jwtdecodejava.exceptions.JWTException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class Utils {

    public static String base64Decode(String string) throws JWTException {
        String decoded;
        try {
            decoded = StringUtils.newStringUtf8(Base64.decodeBase64(string));
        } catch (NullPointerException e) {
            throw new JWTException("Received bytes didn't correspond to a valid Base64 encoded string.", e);
        }
        return decoded;
    }

    public static String base64Encode(String string) throws JWTException {
        String encoded;
        try {
            encoded = StringUtils.newStringUtf8(Base64.encodeBase64(string.getBytes(), false, true));
        } catch (NullPointerException e) {
            throw new JWTException("Received bytes didn't correspond to a valid Base64 encoded string.", e);
        }
        return encoded;
    }

    public static String[] splitToken(String token) {
        String[] parts = token.split("\\.");
        if (parts.length == 2 && token.endsWith(".")) {
            //Tokens with alg='none' have empty String as Signature.
            parts = new String[]{parts[0], parts[1], ""};
        }
        if (parts.length != 3) {
            throw new JWTException(String.format("The token was expected to have 3 parts, but got %s.", parts.length));
        }
        return parts;
    }

    public static boolean verifyHS(HSAlgorithm algorithm, String[] jwtParts, String secret) throws NoSuchAlgorithmException, InvalidKeyException {
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

    public static boolean verifyRS(RSAlgorithm algorithm, String[] jwtParts, PublicKey publicKey) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
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
