package com.auth0.jwt.benchmark;

import com.auth0.jwt.JWTSigner;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;

/**
 *
 * @author sibay
 */
public class JwtBenchmark {
	

	public static String THE_SECRET = "aSecretFromHell";
	
	public static Map payload(long counter) {
		Map json = new HashMap();
		json.put("email", "a@mail.com");
		json.put("name", "my name");
		json.put("street", "a big street");
		json.put("id", counter);
		return json;
	}

	@State(Scope.Benchmark)
	public static class Provider {
		public Random random = new Random(815);
		public com.auth0.jwt.old.JWTSigner signerLeagcy = new com.auth0.jwt.old.JWTSigner(THE_SECRET);
		public com.auth0.jwt.JWTSigner signer = new com.auth0.jwt.JWTSigner(THE_SECRET);
		public String token =  "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyaWQiOiIxMjM0NVVJRDk4NyIsImVtYWlsIjoibXkubmFtZUBtYWlsLm9yZyJ9.D-b6qOjUUZ_gnDU0p3w6nk51Gi-a2a4bOTspAgo3ZLg";
	}
	
	@Benchmark
	public String signOld(Provider prov) throws Exception {
		com.auth0.jwt.old.JWTSigner signer = new com.auth0.jwt.old.JWTSigner(THE_SECRET);
		String token = signer.sign(payload(prov.random.nextInt()));
		return token;
	}

	@Benchmark
	public String  signNew(Provider prov) throws Exception {
		com.auth0.jwt.JWTSigner jwt = new com.auth0.jwt.JWTSigner(THE_SECRET);
		String token  = jwt.sign(payload(prov.random.nextInt()));
		return token;
	}
	
	@Benchmark
	public Map<String, Object> roundtripOld(Provider prov) throws Exception {
		com.auth0.jwt.old.JWTSigner signer = new com.auth0.jwt.old.JWTSigner(THE_SECRET);
		String token = signer.sign(payload(prov.random.nextInt()));
		com.auth0.jwt.old.JWTVerifier verifier = new com.auth0.jwt.old.JWTVerifier(THE_SECRET);
		Map<String, Object> verifiedPayload = verifier.verify(token);
		return verifiedPayload;
	}

	@Benchmark
	public Map<String, Object>  roundtripNew(Provider prov) throws Exception {
		com.auth0.jwt.JWTSigner jwt = new com.auth0.jwt.JWTSigner(THE_SECRET);
		String token  = jwt.sign(payload(prov.random.nextInt()));
		com.auth0.jwt.JWTVerifier verifier = new com.auth0.jwt.JWTVerifier(THE_SECRET);
		Map<String, Object> verifiedPayload = verifier.verify(token);
		return verifiedPayload;
	}
	
	@Benchmark
	public Map verifyNew(Provider prov) throws Exception {
		com.auth0.jwt.JWTVerifier verifier = new com.auth0.jwt.JWTVerifier(THE_SECRET);
		Map<String, Object> verifiedPayload = verifier.verify(prov.token);
		return verifiedPayload;
	}

	@Benchmark
	public Map  verifyOld(Provider prov) throws Exception {
		com.auth0.jwt.old.JWTVerifier verifier = new com.auth0.jwt.old.JWTVerifier(THE_SECRET);
		Map<String, Object> verifiedPayload = verifier.verify(prov.token);
		return verifiedPayload;		
	}

	@Benchmark
	public String signerReuseOld(Provider prov) throws Exception {
		String token = prov.signerLeagcy.sign(payload(prov.random.nextInt()));
		return token;
	}

	@Benchmark
	public String  signerReuseNew(Provider prov) throws Exception {
		String token  = prov.signer.sign(payload(prov.random.nextInt()));
		return token;
	}
}
