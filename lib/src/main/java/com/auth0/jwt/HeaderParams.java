package com.auth0.jwt;

/**
 * Contains constants representing the JWT header parameter names.
 */
public final class HeaderParams {

    private HeaderParams() {}

    /**
     * The algorithm used to sign a JWT.
     */
    public static String ALGORITHM = "alg";

    /**
     * The content type of the JWT.
     */
    public static String CONTENT_TYPE = "cty";

    /**
     * The media type of the JWT.
     */
    public static String TYPE = "typ";

    /**
     * The key ID of a JWT used to specify the key for signature validation.
     */
    public static String KEY_ID = "kid";
}
