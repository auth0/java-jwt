package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;

public class JWTSigner {

    public String sign(String headerJson, String payloadJson) {
        String header = SignUtils.base64Encode(headerJson.getBytes());
        String payload = SignUtils.base64Encode(payloadJson.getBytes());
        String content = String.format("%s.%s", header, payload);
        Algorithm algorithm = Algorithm.HMAC256("secret");

        byte[] signatureBytes = algorithm.sign(content.getBytes());
        String signature = SignUtils.base64Encode(signatureBytes);

        return String.format("%s.%s", content, signature);
    }
}
