package com.auth0.jwt;

import com.auth0.jwt.impl.BasicPayloadHandler;
import com.auth0.jwt.impl.JwtProxyImpl;
import org.junit.Test;

/**
 * Test harness for JwtProxy
 */
public class TestHarness {

	@Test
	public void testHarness() throws Exception {
		
		final String secret = "This is a secret";
		final Algorithm algorithm = Algorithm.HS256;
		
		User user = new User();
		user.setUsername("jwt");
		user.setPassword("mypassword");
		
		JwtProxy proxy = new JwtProxyImpl();
		proxy.setPayloadHandler(new BasicPayloadHandler());
		
		ClaimSet claimSet = new ClaimSet();
		claimSet.setExp(24 * 60 * 60); // expire in 24 hours
		String token = proxy.encode(algorithm, user, secret, claimSet);
		System.out.println(token);
		
		Object payload = proxy.decode(algorithm, token, secret);
		System.out.println(payload);
	}
}
