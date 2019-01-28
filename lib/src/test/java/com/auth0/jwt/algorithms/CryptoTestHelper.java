package com.auth0.jwt.algorithms;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.Charsets;
import org.apache.commons.codec.binary.Base64;

public abstract class CryptoTestHelper {

    private static final Pattern authHeaderPattern = Pattern.compile("^([\\w-]+)\\.([\\w-]+)\\.([\\w-]+)");

	public static String asJWT(Algorithm algorithm, String header, String payload) {
	    byte[] signatureBytes = algorithm.sign(header.getBytes(Charsets.UTF_8), payload.getBytes(Charsets.UTF_8));
	    String jwtSignature = Base64.encodeBase64URLSafeString(signatureBytes);
	    System.out.println("\n" + jwtSignature);
	    return String.format("%s.%s.%s", header, payload, jwtSignature);
	}
	
	public static void assertSignatureValue(String jwt, String expectedSignature) {
		String jwtSignature = jwt.substring(jwt.lastIndexOf('.') + 1);
        assertThat(jwtSignature, is(expectedSignature));
	}
	
	public static void assertSignaturePresent(String jwt) {
        Matcher matcher = authHeaderPattern.matcher(jwt);
        if (!matcher.find() || matcher.groupCount() < 3) {
            fail("No signature present in " + jwt);
        }
        
        assertThat(matcher.group(3), not(is(emptyString())));
	}
}
