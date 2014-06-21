package com.auth0.jwt.impl;

import java.util.Map;

import org.apache.commons.codec.binary.Base64;

import com.auth0.jwt.Algorithm;
import com.auth0.jwt.ClaimSet;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.JwtProxy;
import com.auth0.jwt.JwtSigner;
import com.auth0.jwt.PayloadHandler;

/**
 * JwtProxy implementation
 */
public class JwtProxyImpl implements JwtProxy {

	// the payload identifier in the JSON object
	private static final String PAYLOAD_ID = "payload";
	private PayloadHandler payloadHandler;
	
	public void setPayloadHandler(PayloadHandler payloadHandler) {
		this.payloadHandler = payloadHandler;
	}

	public PayloadHandler getPayloadHandler() {
		return payloadHandler;
	}

	/**
	 * Create a JSON web token by serializing a java object
	 */
	public String encode(Algorithm algorithm, Object obj, String secret,
			ClaimSet claimSet) throws Exception {
		
		JwtSigner jwtSigner = new JwtSigner();
		String payload = getPayloadHandler().encoding(obj);
		
		return jwtSigner.encode(algorithm, payload, PAYLOAD_ID, secret, claimSet);
	}

	/**
	 * Verify a JSON web token and return the object serialized in the JSON payload
	 */
	public Object decode(Algorithm algorithm, String token, String secret)
			throws Exception {
		
		JWTVerifier jwtVerifier = new JWTVerifier(Base64.encodeBase64String(secret.getBytes()));
		Map<String, Object> verify = jwtVerifier.verify(token);
		String payload = (String) verify.get(PAYLOAD_ID);
		
		return getPayloadHandler().decoding(payload);
	}
}
