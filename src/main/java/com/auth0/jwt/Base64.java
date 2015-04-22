package com.auth0.jwt;

import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Created by Chris Thielen on 4/21/15.
 * MIT License
 */
public class Base64 {
    private static final ObjectMapper mapper = new ObjectMapper();

    public static String encodeBase64URLSafe(byte[] binaryData) {
        return Base64Variants.MODIFIED_FOR_URL.encode(binaryData);
    }

    public static byte[] decodeBase64(String base64String) {
        int missingPadCount = base64String.length() % 4;
        String pad;
        switch (missingPadCount) {
            case 1:
                pad = "==="; break;
            case 2:
                pad = "=="; break;
            case 3:
                pad = "="; break;
            default:
                pad = "";
        }
        base64String = base64String.replaceAll("-", "+").replaceAll("_", "/");
        if (missingPadCount > 0) {
            base64String += pad;
        }

        return mapper.convertValue(base64String, byte[].class);
    }
}
