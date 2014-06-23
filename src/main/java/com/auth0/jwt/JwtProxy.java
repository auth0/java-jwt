package com.auth0.jwt;

public interface JwtProxy {
	
	void setPayloadHandler(PayloadHandler payloadHandler);
	String encode(Algorithm algorithm, Object obj, String secret, ClaimSet claimSet) throws Exception;
	Object decode(Algorithm algorithm, String token, String secret) throws Exception;
}
