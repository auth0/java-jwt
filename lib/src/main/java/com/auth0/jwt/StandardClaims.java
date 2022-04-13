package com.auth0.jwt;

/**
 * Contains constants representing the name of the Registered Claim Names as defined in Section 4.1.1 of
 * <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1">RFC 7529</a>
 */
public final class StandardClaims {

    private StandardClaims() {
    }

    /**
     * The "iss" (issuer) claim identifies the principal that issued the JWT.
     */
    public static String ISSUER = "iss";

    /**
     * The "sub" (subject) claim identifies the principal that is the subject of the JWT.
     */
    public static String SUBJECT = "sub";

    /**
     * The "aud" (audience) claim identifies the recipients that the JWT is intended for.
     */
    public static String AUDIENCE = "aud";

    /**
     * The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be
     * accepted for processing.
     */
    public static String EXPIRES_AT = "exp";

    /**
     * The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing.
     */
    public static String NOT_BEFORE = "nbf";

    /**
     * The "iat" (issued at) claim identifies the time at which the JWT was issued.
     */
    public static String ISSUED_AT = "iat";

    /**
     * The "jti" (JWT ID) claim provides a unique identifier for the JWT.
     */
    public static String JWT_ID = "jti";

}
