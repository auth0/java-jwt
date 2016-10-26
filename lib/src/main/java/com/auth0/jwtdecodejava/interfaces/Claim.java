package com.auth0.jwtdecodejava.interfaces;

import com.auth0.jwtdecodejava.exceptions.JWTException;
import com.sun.istack.internal.Nullable;

import java.util.Date;
import java.util.List;

public interface Claim {

    boolean isNull();

    /**
     * Get this Claim as a Boolean.
     * If the value isn't of type Boolean or it can't be converted to a Boolean, null will be returned.
     *
     * @return the value as a Boolean or null.
     */
    @Nullable
    Boolean asBoolean();

    /**
     * Get this Claim as an Integer.
     * If the value isn't of type Integer or it can't be converted to an Integer, null will be returned.
     *
     * @return the value as an Integer or null.
     */
    @Nullable
    Integer asInt();

    /**
     * Get this Claim as a Double.
     * If the value isn't of type Double or it can't be converted to a Double, null will be returned.
     *
     * @return the value as a Double or null.
     */
    @Nullable
    Double asDouble();

    /**
     * Get this Claim as a String.
     * If the value isn't of type String or it can't be converted to a String, null will be returned.
     *
     * @return the value as a String or null.
     */
    @Nullable
    String asString();

    /**
     * Get this Claim as a Date.
     * If the value can't be converted to a Date, null will be returned.
     *
     * @return the value as a Date or null.
     */
    @Nullable
    Date asDate();

    /**
     * Get this Claim as an Array of type T.
     * If the value isn't an Array, an empty Array will be returned.
     *
     * @return the value as an Array or an empty Array.
     * @throws Exception if the values inside the Array can't be converted to a class T.
     */
    <T> T[] asArray(Class<T> tClazz) throws JWTException;

    /**
     * Get this Claim as a List of type T.
     * If the value isn't an Array, an empty List will be returned.
     *
     * @return the value as a List or an empty List.
     * @throws Exception if the values inside the List can't be converted to a class T.
     */
    <T> List<T> asList(Class<T> tClazz) throws JWTException;
}
