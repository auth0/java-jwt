package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;

@SuppressWarnings("WeakerAccess")
public abstract class JWT implements DecodedJWT {

    /**
     * Decode a given JWT token.
     * <p>
     * Note that this method <b>doesn't verify the token's signature!</b> Use it only if you trust the token or you already verified it.
     *
     * @param token with jwt format as string.
     * @return a decoded token.
     * @throws JWTDecodeException if any part of the token contained an invalid jwt or JSON format of each of the jwt parts.
     */
    public static JWT decode(String token) throws JWTDecodeException {
        return new JWTDecoder(token);
    }

    /**
     * Returns a {@link JWTVerifier} builder with the algorithm to be used to validate token signature.
     *
     * @param algorithm that will be used to verify the token's signature.
     * @return {@link JWTVerifier} builder
     * @throws IllegalArgumentException if the provided algorithm is null.
     */
    public static Verification require(Algorithm algorithm) {
        return JWTVerifier.init(algorithm);
    }

    /**
     * Returns a JWT builder used to create and sign jwt tokens
     *
     * @return a jwt token builder.
     */
    public static JWTCreator.Builder create() {
        return JWTCreator.init();
    }
}
