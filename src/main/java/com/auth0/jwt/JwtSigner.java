package com.auth0.jwt;

import java.util.ArrayList;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.OperationNotSupportedException;

import org.apache.commons.codec.binary.Base64;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * JwtSigner implementation based on the Ruby implementation from http://jwt.io
 * No support for RSA encryption at present
 */
public class JwtSigner {
	
	/**
	 * Generate a JSON web token based on a payload, secret key and claim set
	 */
	public String encode(Algorithm algorithm, String payload, String payloadId, String key,
			ClaimSet claimSet) throws Exception {

		List<String> segments = new ArrayList<String>();
		
		segments.add(encodedHeader(algorithm));
		segments.add(encodedPayload(payload, payloadId, claimSet));
		segments.add(encodedSignature(join(segments, "."), key, algorithm));
		
		return join(segments, ".");
	}
	
	/**
	 * Generate the header part of a JSON web token 
	 */
	private String encodedHeader(Algorithm algorithm)
			throws Exception {
		
		if (algorithm == null) { // default the algorithm if not specified
			algorithm = Algorithm.HS256;
		}

		// create the header
		ObjectNode header = JsonNodeFactory.instance.objectNode();
		header.put("type", "JWT");
		header.put("alg", algorithm.name());

		return base64UrlEncode(header.toString().getBytes());
	}

	/**
	 * Generate the JSON web token payload, merging it with the claim set 
	 */
	private String encodedPayload(String payload, String payloadId, ClaimSet claimSet) throws Exception {
		
		ObjectNode _claimSet = JsonNodeFactory.instance.objectNode();
		ObjectNode _payload = JsonNodeFactory.instance.objectNode();;
		
		_payload.put(payloadId, payload);
		
		if(claimSet != null) {
			if(claimSet.getExp() > 0) {
				_claimSet.put("exp", claimSet.getExp());
			}
			_payload.putAll(_claimSet);
		}
		
		return base64UrlEncode(_payload.toString().getBytes());
	}

	/**
	 * Sign the header and payload
	 */
	private String encodedSignature(String signingInput, String key,
			Algorithm algorithm) throws Exception {
		
		byte[] signature = sign(algorithm, signingInput, key);
		return base64UrlEncode(signature);
	}

	/**
	 * Safe URL encode a byte array to a String
	 */
	private String base64UrlEncode(byte[] str) throws Exception {
		
		return new String(Base64.encodeBase64URLSafe(str));
	}

	/**
	 * Switch the signing algorithm based on input, RSA not supported
	 */
	private byte[] sign(Algorithm algorithm, String msg, String key)
			throws Exception {
		
		switch (algorithm) {
		case HS256:
		case HS384:
		case HS512:
			return signHmac(algorithm, msg, key);
		case RS256:
		case RS384:
		case RS512:
		default:
			throw new OperationNotSupportedException(
					"Unsupported signing method");
		}
	}

	/**
	 * Sign an input string using HMAC and return the encrypted bytes
	 */
	private byte[] signHmac(Algorithm algorithm, String msg, String key)
			throws Exception {

		Mac mac = Mac.getInstance(algorithm.getValue());
		mac.init(new SecretKeySpec(key.getBytes(), algorithm.getValue()));
		return mac.doFinal(msg.getBytes());
	}
	
	/**
	 * Mimick the ruby array.join function 
	 */
	private String join(List<String> input, String on) {

		int size = input.size();
		int count = 1;
		StringBuilder joined = new StringBuilder();
		for (String string : input) {
			joined.append(string);
			if (count < size) {
				joined.append(on);
			}
			count++;
		}

		return joined.toString();
	}
}
