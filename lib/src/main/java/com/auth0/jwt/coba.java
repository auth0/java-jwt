package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;

import java.util.HashMap;

public class coba {
    public static void main(String[] args) {
        HashMap<String, Object> payload = new HashMap<>();
        payload.put("name", "andy");
        payload.put("age", 24);

        JWTCreator.Builder builder = JWT.create().withCustomClaim(payload);
        String jwt = builder.sign(Algorithm.HMAC256("secret"));
        System.out.printf("jwt %s", jwt);
    }

}

