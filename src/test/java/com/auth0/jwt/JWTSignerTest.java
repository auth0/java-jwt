package com.auth0.jwt;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;

import org.junit.Ignore;
import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class JWTSignerTest {
	private static String secret = "my secret";
	
    private static JWTSigner signer = new JWTSigner(secret);
    
    @Test
    public void shouldSignEmpty() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        
        // When        
        String token = signer.sign(claims);
        
        // Then
        ObjectMapper mapper = new ObjectMapper();		
        ObjectNode node = mapper.createObjectNode();
        node.put("typ", "JWT");
        node.put("alg", Algorithm.HS256.name());
        
		String header = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		node = JsonNodeFactory.instance.objectNode();
		String payload = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		String msg = header + "." + payload;
		String hmac = JWTSigner.base64UrlEncode(JWTSigner.sign(Algorithm.HS256, msg, secret));
		String jws = msg + "." +hmac;
				
        assertEquals(jws, token);
    }

    @Test
    public void shouldSignEmptyTwoParams() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        
        // When
        String token = signer.sign(claims);
        
        // Then
        ObjectMapper mapper = new ObjectMapper();		
        ObjectNode node = mapper.createObjectNode();
        node.put("typ", "JWT");
        node.put("alg", Algorithm.HS256.name());
        
		String header = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		node = JsonNodeFactory.instance.objectNode();
		String payload = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		String msg = header + "." + payload;
		String hmac = JWTSigner.base64UrlEncode(JWTSigner.sign(Algorithm.HS256, msg, secret));
		String jws = msg + "." +hmac;
		
        assertEquals(jws, token);
    }
    
    @Test
    public void shouldSignStringOrURI1() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("iss", "foo");
        
        // When
        String token = signer.sign(claims);        
        
        // Then
        ObjectMapper mapper = new ObjectMapper();		
        ObjectNode node = mapper.createObjectNode();
        node.put("typ", "JWT");
        node.put("alg", Algorithm.HS256.name());
        
		String header = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		node = JsonNodeFactory.instance.objectNode();
        node.put("iss",  "foo");
		String payload = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		String msg = header + "." + payload;
		String hmac = JWTSigner.base64UrlEncode(JWTSigner.sign(Algorithm.HS256, msg, secret));
		String jws = msg + "." +hmac;
		
        assertEquals(jws, token);
    }
    
    @Test
    public void shouldSignStringOrURI2() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("sub", "http://foo");
        
        // When
        String token = signer.sign(claims);
        
        // Then
        ObjectMapper mapper = new ObjectMapper();		
        ObjectNode node = mapper.createObjectNode();
        node.put("typ", "JWT");
        node.put("alg", Algorithm.HS256.name());
        
		String header = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		node = JsonNodeFactory.instance.objectNode();
        node.put("sub",  "http://foo");
		String payload = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		String msg = header + "." + payload;
		String hmac = JWTSigner.base64UrlEncode(JWTSigner.sign(Algorithm.HS256, msg, secret));
		String jws = msg + "." +hmac;
		
        assertEquals(jws, token);
    }
    
    @Test
    public void shouldSignStringOrURI3() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("aud", "");
        
        // When
        String token = signer.sign(claims);
        
        // Then
        ObjectMapper mapper = new ObjectMapper();		
        ObjectNode node = mapper.createObjectNode();
        node.put("typ", "JWT");
        node.put("alg", Algorithm.HS256.name());
        
		String header = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		node = JsonNodeFactory.instance.objectNode();
        node.put("aud",  "");
		String payload = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		String msg = header + "." + payload;
		String hmac = JWTSigner.base64UrlEncode(JWTSigner.sign(Algorithm.HS256, msg, secret));
		String jws = msg + "." +hmac;
		
        assertEquals(jws, token);
    }
    
    @Test
    public void shouldSignStringOrURICollection() throws Exception {
        // Given
    	HashMap<String, Object> claims = new HashMap<String, Object>();
        LinkedList<String> aud = new LinkedList<String>();
        aud.add("xyz");
        aud.add("ftp://foo");
        claims.put("aud", aud);
        
        // When
        String token = signer.sign(claims);
        
        // Then
        ObjectMapper mapper = new ObjectMapper();		
        ObjectNode node = mapper.createObjectNode();
        node.put("typ", "JWT");
        node.put("alg", Algorithm.HS256.name());
        
		String header = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		node = JsonNodeFactory.instance.objectNode();
        node.put("aud",  mapper.createArrayNode().add("xyz").add("ftp://foo"));
        
		String payload = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		String msg = header + "." + payload;
		String hmac = JWTSigner.base64UrlEncode(JWTSigner.sign(Algorithm.HS256, msg, secret));
		String jws = msg + "." +hmac;
		
        assertEquals(jws, token);
    }
    
    @Test
    public void shouldSignIntDate1() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("exp", 123);
        
        // When
        String token = signer.sign(claims);
        
        // Then
        ObjectMapper mapper = new ObjectMapper();		
        ObjectNode node = mapper.createObjectNode();
        node.put("typ", "JWT");
        node.put("alg", Algorithm.HS256.name());
        
		String header = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		node = JsonNodeFactory.instance.objectNode();
        node.put("exp",  123);
        
		String payload = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		String msg = header + "." + payload;
		String hmac = JWTSigner.base64UrlEncode(JWTSigner.sign(Algorithm.HS256, msg, secret));
		String jws = msg + "." +hmac;
		
        assertEquals(jws, token);
    }

    @Test
    public void shouldSignIntDate2() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("nbf", 0);
        
        // When
        String token = signer.sign(claims);
        
        // Then
        ObjectMapper mapper = new ObjectMapper();		
        ObjectNode node = mapper.createObjectNode();
        node.put("typ", "JWT");
        node.put("alg", Algorithm.HS256.name());
        
		String header = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		node = JsonNodeFactory.instance.objectNode();
        node.put("nbf",  0);
        
		String payload = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		String msg = header + "." + payload;
		String hmac = JWTSigner.base64UrlEncode(JWTSigner.sign(Algorithm.HS256, msg, secret));
		String jws = msg + "." +hmac;
		
        assertEquals(jws, token);
    }
    
    @Test
    public void shouldSignIntDate3() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("iat", Long.MAX_VALUE);
        
        // When
        String token = signer.sign(claims);
        
        // Then
        ObjectMapper mapper = new ObjectMapper();		
        ObjectNode node = mapper.createObjectNode();
        node.put("typ", "JWT");
        node.put("alg", Algorithm.HS256.name());
        
		String header = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		node = JsonNodeFactory.instance.objectNode();
        node.put("iat",  Long.MAX_VALUE);
        
		String payload = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		String msg = header + "." + payload;
		String hmac = JWTSigner.base64UrlEncode(JWTSigner.sign(Algorithm.HS256, msg, secret));
		String jws = msg + "." +hmac;
		
        assertEquals(jws, token);
    }
    
    @Test
    public void shouldSignString() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("jti", "foo");
        
        // When
        String token = signer.sign(claims);
        
        // Then
        ObjectMapper mapper = new ObjectMapper();		
        ObjectNode node = mapper.createObjectNode();
        node.put("typ", "JWT");
        node.put("alg", Algorithm.HS256.name());
        
		String header = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		node = JsonNodeFactory.instance.objectNode();
        node.put("jti",  "foo");
        
		String payload = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		String msg = header + "." + payload;
		String hmac = JWTSigner.base64UrlEncode(JWTSigner.sign(Algorithm.HS256, msg, secret));
		String jws = msg + "." +hmac;
		
        assertEquals(jws, token);
    }
    
    @Test
    public void shouldSignNullEqualsMissing() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        for (String claimName : Arrays.asList("iss", "sub", "aud", "exp", "nbf", "iat", "jti")) {
            claims.put(claimName, null);
        }
        
        // When
        String token = signer.sign(claims);
        
        // Then
        ObjectMapper mapper = new ObjectMapper();		
        ObjectNode node = mapper.createObjectNode();
        node.put("typ", "JWT");
        node.put("alg", Algorithm.HS256.name());
        
		String header = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		node = JsonNodeFactory.instance.objectNode();
        
		String payload = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		String msg = header + "." + payload;
		String hmac = JWTSigner.base64UrlEncode(JWTSigner.sign(Algorithm.HS256, msg, secret));
		String jws = msg + "." +hmac;
		
        assertEquals(jws, token);
    }
    
    @Test(expected = Exception.class)
    public void shouldFailExpectStringOrURI1() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("iss", 0);
        
        // When
        signer.sign(claims);
        
        // Then        
    }
    
    @Test(expected = Exception.class)
    public void shouldFailExpectStringOrURI2() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("sub", ":");
        
        // When
        signer.sign(claims);
        
        // Then
    }
    
    @Test(expected = Exception.class)
    public void shouldFailExpectStringOrURICollection1() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("aud", 0);
        
        // When
        signer.sign(claims);
        
        // Then
    }
    
    @Test(expected = Exception.class)
    public void shouldFailExpectStringOrURICollection2() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("aud", Arrays.asList(0));
        
        // When
        signer.sign(claims);
        
        // Then
    }
    
    @Test(expected = Exception.class)
    public void shouldFailExpectStringOrURICollection3() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("aud", Arrays.asList(":"));
        
        // When
        signer.sign(claims);
        
        // Then
    }
    
    @Test(expected = Exception.class)
    public void shouldFailExpectIntDate1() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("exp", -1);
        
        // When
        signer.sign(claims);
        
        // Then
    }
    
    @Test(expected = Exception.class)
    public void shouldFailExpectIntDate2() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("nbf", "100");
        
        // When
        signer.sign(claims);
        
        // Then
    }
    
    @Test(expected = Exception.class)
    public void shouldFailExpectString() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        claims.put("jti", 100);
        
        // When
        signer.sign(claims);
        
        // Then
    }
    
    @Test
    public void shouldOptionsNone() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        
        // When
        String token = signer.sign(claims, new JWTSigner.Options());
        
        // Then
        ObjectMapper mapper = new ObjectMapper();		
        ObjectNode node = mapper.createObjectNode();
        node.put("typ", "JWT");
        node.put("alg", Algorithm.HS256.name());
        
		String header = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		node = JsonNodeFactory.instance.objectNode();
		
		String payload = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		String msg = header + "." + payload;
		String hmac = JWTSigner.base64UrlEncode(JWTSigner.sign(Algorithm.HS256, msg, secret));
		String jws = msg + "." +hmac;
		
        assertEquals(jws, token);
    }
    
    @Test
    public void shouldOptionsAll() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        
        // When
        signer.sign(claims, new JWTSigner.Options()
                .setExpirySeconds(1000).setNotValidBeforeLeeway(5)
                .setIssuedAt(true).setJwtId(true));
    }

    @Test
    @Ignore
    public void shouldOptionsAlgorithm() throws Exception {
    	// Given
        HashMap<String, Object> claims = new HashMap<String, Object>();
        
        // When
        String token = signer.sign(claims,
                new JWTSigner.Options().setAlgorithm(Algorithm.HS512));
        
        // Then
        ObjectMapper mapper = new ObjectMapper();		
        ObjectNode node = mapper.createObjectNode();
        node.put("typ", "JWT");
        node.put("alg", Algorithm.HS512.name());
        
		String header = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		node = JsonNodeFactory.instance.objectNode();
        
		String payload = JWTSigner.base64UrlEncode(node.toString().getBytes("UTF-8"));
		
		String msg = header + "." + payload;
		String hmac = JWTSigner.base64UrlEncode(JWTSigner.sign(Algorithm.HS512, msg, secret));
		String jws = msg + "." +hmac;
		
        assertEquals(jws, token);
    }

}
