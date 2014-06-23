package com.auth0.jwt.impl;

import com.auth0.jwt.PayloadHandler;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Basic implementation of a payload handler which serializes the payload to a String, and echoes it for deserialization
 */
public final class BasicPayloadHandler implements PayloadHandler {

	public String encoding(Object payload) throws Exception {
		return new ObjectMapper().writeValueAsString(payload);
	}
	
	public Object decoding(String payload) throws Exception {
		return payload;
	}
}
