package com.auth0.jwt.algorithms;

import org.apache.commons.codec.binary.Base64;

public class AlgorithmUtils {

    public static void verify(Algorithm algorithm, String jwt) {
        String[] parts = jwt.split("\\.");
        byte[] content = String.format("%s.%s", parts[0], parts[1]).getBytes();
        byte[] signature = new byte[0];
        if (parts.length == 3) {
            signature = Base64.decodeBase64(parts[2]);
        }
        algorithm.verify(content, signature);
    }
}
