package com.auth0.msg;

/**
 * Different types of request/response
 */
public enum MessageType {
    AUTHORIZATION_REQUEST, AUTHORIZATION_RESPONSE, TOKEN_RESPONSE,
    REFRESH_TOKEN_REQUEST, REFRESH_TOKEN_RESPONSE, USER_INFO;
}