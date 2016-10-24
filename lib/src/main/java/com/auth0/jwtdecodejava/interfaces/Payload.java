package com.auth0.jwtdecodejava.interfaces;

import com.sun.istack.internal.NotNull;
import com.sun.istack.internal.Nullable;

import java.util.Date;
import java.util.Map;

public interface Payload {

    /**
     * Get the value of the "iss" claim, or null if it's not available.
     *
     * @return the Issuer value or null.
     */
    @Nullable
    String getIssuer();

    /**
     * Get the value of the "sub" claim, or null if it's not available.
     *
     * @return the Subject value or null.
     */
    @Nullable
    String getSubject();

    /**
     * Get the value of the "aud" claim, or null if it's not available.
     *
     * @return the Audience value or null.
     */
    @Nullable
    String[] getAudience();

    /**
     * Get the value of the "exp" claim, or null if it's not available.
     *
     * @return the Expiration Time value or null.
     */
    @Nullable
    Date getExpiresAt();

    /**
     * Get the value of the "nbf" claim, or null if it's not available.
     *
     * @return the Not Before value or null.
     */
    @Nullable
    Date getNotBefore();

    /**
     * Get the value of the "iat" claim, or null if it's not available.
     *
     * @return the Issued At value or null.
     */
    @Nullable
    Date getIssuedAt();

    /**
     * Get the value of the "jti" claim, or null if it's not available.
     *
     * @return the Payload ID value or null.
     */
    @Nullable
    String getId();

    /**
     * Get a Private Claim given it's name. If the Claim wasn't specified in the Payload payload, null will be returned.
     *
     * @param name the name of the Claim to retrieve.
     * @return the Claim if found or null.
     */
    @Nullable
    public Claim getClaim(@NotNull String name);
}
