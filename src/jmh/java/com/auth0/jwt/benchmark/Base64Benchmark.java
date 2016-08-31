package com.auth0.jwt.benchmark;

import java.io.UnsupportedEncodingException;
import java.util.Base64;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.infra.Blackhole;

/**
 *
 * @author sibay
 */
public class Base64Benchmark {
	
	@State(Scope.Benchmark)
	public static class JdkBase64 {
		public Base64.Encoder encoder = Base64.getEncoder();
		public Base64.Decoder decoder = Base64.getDecoder();
		public final Base64.Encoder urlEncoder = Base64.getUrlEncoder().withoutPadding();
	    public final Base64.Decoder urlDecoder = Base64.getUrlDecoder();
	}
	
	@State(Scope.Benchmark)
	public static class ApaBase64 {
		public final org.apache.commons.codec.binary.Base64 apaUrlDecoder = new org.apache.commons.codec.binary.Base64(true);
	}
	
	public static long counterJdk=0;
	public static long counterApa=0;
	
	@Benchmark
	public void roundtripJdk(JdkBase64 jdkBase64, Blackhole bh) throws UnsupportedEncodingException {
		counterJdk++;
		if ( counterJdk > Long.MAX_VALUE - 100.000 ) {
			counterJdk = 0;
		}
		String token = "{like:some json, without:quotes,they: are annoying, to:type in: Java Strings}" + String.valueOf(counterJdk);
		String base64 = jdkBase64.encoder.encodeToString(token.getBytes("UTF-8"));
		bh.consume(base64);
		byte[] decoded = jdkBase64.decoder.decode(base64);
		bh.consume(decoded);
	}
	
	@Benchmark
	public void roundtripUrlJdk(JdkBase64 jdkBase64, Blackhole bh) throws UnsupportedEncodingException {
		counterJdk++;
		if ( counterJdk > Long.MAX_VALUE - 100.000 ) {
			counterJdk = 0;
		}
		String token = "{like:some json, without:quotes,they: are annoying, to:type in: Java Strings}" + String.valueOf(counterJdk);
		String base64 = jdkBase64.urlEncoder.encodeToString(token.getBytes("UTF-8"));
		bh.consume(base64);
		byte[] decoded = jdkBase64.urlDecoder.decode(base64);
		bh.consume(decoded);
	}
	
	@Benchmark
	public void roundtripApache(JdkBase64 decodec, Blackhole bh) throws UnsupportedEncodingException {
		counterApa++;
		if ( counterApa > Long.MAX_VALUE - 100.000 ) {
			counterApa = 0;
		}
		String token = "{like:some json, without:quotes,they: are annoying, to:type in: Java Strings}" + String.valueOf(counterApa);
		String base64 = org.apache.commons.codec.binary.Base64.encodeBase64String(token.getBytes("UTF-8"));
		bh.consume(base64);
		byte[] decoded = org.apache.commons.codec.binary.Base64.decodeBase64(base64);
		bh.consume(decoded);
	}

	@Benchmark
	public void roundtripUrlApache(ApaBase64 decodec, Blackhole bh) throws UnsupportedEncodingException {
		counterApa++;
		if ( counterApa > Long.MAX_VALUE - 100.000 ) {
			counterApa = 0;
		}
		String token = "{like:some json, without:quotes,they: are annoying, to:type in: Java Strings}" + String.valueOf(counterApa);
		String base64 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(token.getBytes("UTF-8"));
		bh.consume(base64);
		byte[] decoded =decodec.apaUrlDecoder.decode(base64);
		bh.consume(decoded);
	}
}
