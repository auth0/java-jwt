package com.auth0.jwt;

/**
 * Abstraction to allow custom payload handling e.g. in the event the payload needs to be encrypted
 */
public interface PayloadHandler {
	
	String encoding(Object payload) throws Exception;
	Object decoding(String payload) throws Exception;
}
