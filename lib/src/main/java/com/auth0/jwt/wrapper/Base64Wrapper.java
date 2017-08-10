package com.auth0.jwt.wrapper;

import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTDecodeException;

import org.apache.commons.codec.binary.Base64;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Base 64 Wrapper to fix https://github.com/auth0/java-jwt/issues/131
 * Use Base64 from Android if on Android environment otherwise use apache commons codec
 * Created by yhuel on 09/08/17.
 */

public class Base64Wrapper {


    /**
     * Android Base64 flag
     * https://developer.android.com/reference/android/util/Base64.html#URL_SAFE
     */
    private static final int FLAG_URL_SAFE = 8;
    /**
     * Android Base64 flag
     * https://developer.android.com/reference/android/util/Base64.html#NO_PADDING
     */
    private static final int FLAG_NO_PADDING = 1;

    public static Base64Wrapper instance = new Base64Wrapper();

    private boolean androidEnvironment;
    private Method androidMethodEncode;
    private Method androidMethodDecode;


    public static Base64Wrapper getInstance() {
        return instance;
    }

    private Base64Wrapper(){
        //check if you are on Android platform
        try {
            //use reflexion to know if you're on Android platform (not very sexy)
            Class<?> androidBase64 = Class.forName("android.util.Base64");
            androidMethodDecode = androidBase64.getMethod("decode",String.class, int.class);
            androidMethodEncode = androidBase64.getMethod("encodeToString", byte[].class, int.class);
            androidEnvironment = true;
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            //nothing to do : not on Android Environment
        }
    }

    public String encode(byte[] data) throws JWTCreationException{
        if(androidEnvironment) {
            try {
                /*
                 * use flags to have same behavior as apache commons codec
                 * see : https://commons.apache.org/proper/commons-codec/apidocs/org/apache/commons/codec/binary/Base64.html#encodeBase64URLSafeString(byte[])
                 */
                return (String)androidMethodEncode.invoke(null,data, FLAG_NO_PADDING|FLAG_URL_SAFE);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new JWTCreationException("Error when encode in Base64 in android environment",e);
            }
        }else{
            return Base64.encodeBase64URLSafeString(data);
        }
    }

    public byte[] decode(String data)  throws JWTDecodeException{
        if(androidEnvironment) {
            try {
                //use same flag FLAG_URL_SAFE as encode method, flag FLAG_NO_PADDING only for encode
                return (byte[])androidMethodDecode.invoke(null,data, FLAG_URL_SAFE);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new JWTCreationException("Error when encode in Base64 in android environment",e);
            }
        }else {
            return Base64.decodeBase64(data);
        }
    }
}
