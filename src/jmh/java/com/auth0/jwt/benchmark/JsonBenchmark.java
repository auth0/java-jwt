package com.auth0.jwt.benchmark;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import org.boon.json.JsonParserAndMapper;
import org.boon.json.JsonParserFactory;
import org.boon.json.JsonSerializer;
import org.boon.json.JsonSerializerFactory;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.infra.Blackhole;

/**
 *
 * @author sibay
 */
public class JsonBenchmark {
	
	public static String jsonString(long counter) {
		return "{ \"payload\":"
				+ "{\n" +
			"  \"sub\": \"1234567890" + String.valueOf(counter) + 
				"\",\n" +
			"  \"name\": \"John Doe\",\n" +
			"  \"admin\": true,\n" +
			"  \"email\": \"this.is.a.long@email.address.com\"\n" +
			"}," +
			"\"header\":"
				+ "{\n" +
				"  \"alg\": \"HS256\",\n" +
				"  \"typ\": \"JWT\",\n" +
				"  \"all\": [\"JWTB\",\"JWTA\"]\n" +
				"}"
			+ "}";
	}
	
	public static Map jsonMap(long counter) {
		Map json = new HashMap();
		json.put("email", "a@mail.com");
		json.put("name", "my name");
		json.put("street", "a big street");
		json.put("id", counter);
		Map header = new HashMap();
		header.put("type", "jwt");
		header.put("alg", "SHA512");
		json.put("header", header);
		return json;
	}
	
	@State(Scope.Benchmark)
	public static class TheRandom {
		public Random random = new Random(1212);
	}
	
	@State(Scope.Benchmark)
	public static class TheFactory {
		public JsonParserAndMapper fastParser = new JsonParserFactory().createFastParser();
		public final JsonSerializer serializer = new JsonSerializerFactory()
							.setSerializeAsSupport(false).useFieldsOnly().create();
		public ObjectMapper jacksonMapper = new ObjectMapper();
		
	}

	@Benchmark
	public void boonStringToMap(TheRandom tr, TheFactory theFactory, Blackhole bh) {
		String json = jsonString(tr.random.nextLong());
		Map<String,Object> jsonRoot = (Map<String,Object>) theFactory.fastParser.parseMap(json);
		assert jsonRoot.get("header") != null;
		bh.consume(jsonRoot);
	}


	@Benchmark
	public void jacksonStringToMap(TheRandom tr, TheFactory theFactory, Blackhole bh) throws IOException {
		String json = jsonString(tr.random.nextLong());
		Map<String,Object> jsonRoot = theFactory.jacksonMapper.readValue(json, Map.class);
		assert jsonRoot.get("header") != null;
		bh.consume(jsonRoot);
	}

	
	@Benchmark
	public void boonMapToString(TheRandom tr, TheFactory theFactory, Blackhole bh) {
		Map json = jsonMap(tr.random.nextLong());
		String jsonString = theFactory.serializer.serialize(json).toString();
		bh.consume(jsonString);
	}

	@Benchmark
	public void jacksonMapToString(TheRandom tr, TheFactory theFactory, Blackhole bh) throws IOException {
		Map json = jsonMap(tr.random.nextLong());
		String jsonString = theFactory.jacksonMapper.writeValueAsString(json);
		bh.consume(jsonString);
	}

}
